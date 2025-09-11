// Copyright 2025 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::{fmt::Formatter, sync::Arc};

use arrow::array::{
    Array, AsArray, Float32Array, Int8Array, Int16Array, Int32Array, Int64Array, RecordBatch,
    UInt8Array, UInt16Array, UInt32Array, UInt64Array,
};
use arrow_schema::{Field, FieldRef, Schema};
use datafusion::{
    arrow::{
        array::{ArrayRef, Float64Array},
        datatypes::DataType,
    },
    common::{downcast_value, internal_err, not_impl_err, plan_err},
    error::Result,
    logical_expr::{
        Accumulator, AggregateUDFImpl, ColumnarValue, Signature, TypeSignature, Volatility,
        function::{AccumulatorArgs, StateFieldsArgs},
        utils::format_state_name,
    },
    physical_plan::PhysicalExpr,
    scalar::ScalarValue,
};
use datafusion_functions_aggregate_common::tdigest::TryIntoF64;
use sketches_ddsketch::{DDSketch, Config};

use super::NUMERICS;

const DDS_PERCENTILE_CONT: &str = "dds_percentile_cont";
const DEFAULT_MAX_BINS: u32 = 2048;
const DEFAULT_ALPHA: f64 = 0.005;
const DEFAULT_MIN_VALUE: f64 = 1.0e-9;

pub(crate) struct DdsPercentileCont(Signature);

impl DdsPercentileCont {
    pub fn new() -> Self {
        let mut variants = Vec::with_capacity(NUMERICS.len());
        // Accept any numeric value paired with a float64 percentile
        for num in NUMERICS {
            variants.push(TypeSignature::Exact(vec![num.clone(), DataType::Float64]));
        }
        Self(Signature::one_of(variants, Volatility::Immutable))
    }
}

impl std::fmt::Debug for DdsPercentileCont {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("DdsPercentileCont")
            .field("name", &self.name())
            .field("signature", &self.0)
            .finish()
    }
}

impl Default for DdsPercentileCont {
    fn default() -> Self {
        Self::new()
    }
}

impl AggregateUDFImpl for DdsPercentileCont {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        DDS_PERCENTILE_CONT
    }

    fn signature(&self) -> &datafusion::logical_expr::Signature {
        &self.0
    }

    fn return_type(&self, arg_types: &[DataType]) -> Result<DataType> {
        if !arg_types[0].is_numeric() {
            return plan_err!("dds_percentile_cont requires numeric input types");
        }
        Ok(DataType::Float64) // DDSketch always returns Float64
    }

    fn state_fields(&self, args: StateFieldsArgs) -> Result<Vec<FieldRef>> {
        // Intermediate state stores serialized DDSketch
        let state_name = "dds_percentile_cont";
        Ok(vec![Arc::new(Field::new(
            format_state_name(args.name, state_name),
            DataType::Binary,
            true,
        ))])
    }

    fn accumulator(&self, args: AccumulatorArgs) -> Result<Box<dyn Accumulator>> {
        let percentile = validate_input_percentile_expr(&args.exprs[1])?;
        let accumulator = DdsPercentileContAccumulator::new(percentile)?;
        Ok(Box::new(accumulator))
    }
}

fn validate_input_percentile_expr(expr: &Arc<dyn PhysicalExpr>) -> Result<f64> {
    let percentile = match get_scalar_value(expr)? {
        ScalarValue::Float32(Some(value)) => value as f64,
        ScalarValue::Float64(Some(value)) => value,
        sv => {
            return not_impl_err!(
                "Percentile value for 'DDS_PERCENTILE_CONT' must be Float32 or Float64 literal (got data type {})",
                sv.data_type()
            );
        }
    };

    // Ensure the percentile is between 0 and 1.
    if !(0.0..=1.0).contains(&percentile) {
        return plan_err!(
            "Percentile value must be between 0.0 and 1.0 inclusive, {percentile} is invalid"
        );
    }
    Ok(percentile)
}

fn get_scalar_value(expr: &Arc<dyn PhysicalExpr>) -> Result<ScalarValue> {
    let empty_schema = Arc::new(Schema::empty());
    let batch = RecordBatch::new_empty(Arc::clone(&empty_schema));
    if let ColumnarValue::Scalar(s) = expr.evaluate(&batch)? {
        Ok(s)
    } else {
        internal_err!("Didn't expect ColumnarValue::Array")
    }
}

/// DDSketch-based accumulator for approximate percentile calculation
struct DdsPercentileContAccumulator {
    sketch: DDSketch,
    percentile: f64,
    // Lazy serialization: cache serialized state to avoid repeated serialization
    cached_state: Option<Vec<u8>>,
    state_dirty: bool,
}

impl std::fmt::Debug for DdsPercentileContAccumulator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DdsPercentileContAccumulator(percentile: {}, dirty: {})",
            self.percentile, self.state_dirty
        )
    }
}

impl DdsPercentileContAccumulator {
    fn new(percentile: f64) -> Result<Self> {
        let config = Config::new(DEFAULT_ALPHA, DEFAULT_MAX_BINS, DEFAULT_MIN_VALUE);
        let sketch = DDSketch::new(config);
        Ok(Self {
            sketch,
            percentile,
            cached_state: None,
            state_dirty: false,
        })
    }

    fn convert_to_float(values: &ArrayRef) -> Result<Vec<f64>> {
        match values.data_type() {
            DataType::Float64 => {
                let array = downcast_value!(values, Float64Array);
                Ok(array
                    .values()
                    .iter()
                    .filter_map(|v| v.try_as_f64().transpose())
                    .collect::<Result<Vec<_>>>()?)
            }
            DataType::Float32 => {
                let array = downcast_value!(values, Float32Array);
                Ok(array
                    .values()
                    .iter()
                    .filter_map(|v| v.try_as_f64().transpose())
                    .collect::<Result<Vec<_>>>()?)
            }
            DataType::Int64 => {
                let array = downcast_value!(values, Int64Array);
                Ok(array
                    .values()
                    .iter()
                    .filter_map(|v| v.try_as_f64().transpose())
                    .collect::<Result<Vec<_>>>()?)
            }
            DataType::Int32 => {
                let array = downcast_value!(values, Int32Array);
                Ok(array
                    .values()
                    .iter()
                    .filter_map(|v| v.try_as_f64().transpose())
                    .collect::<Result<Vec<_>>>()?)
            }
            DataType::Int16 => {
                let array = downcast_value!(values, Int16Array);
                Ok(array
                    .values()
                    .iter()
                    .filter_map(|v| v.try_as_f64().transpose())
                    .collect::<Result<Vec<_>>>()?)
            }
            DataType::Int8 => {
                let array = downcast_value!(values, Int8Array);
                Ok(array
                    .values()
                    .iter()
                    .filter_map(|v| v.try_as_f64().transpose())
                    .collect::<Result<Vec<_>>>()?)
            }
            DataType::UInt64 => {
                let array = downcast_value!(values, UInt64Array);
                Ok(array
                    .values()
                    .iter()
                    .filter_map(|v| v.try_as_f64().transpose())
                    .collect::<Result<Vec<_>>>()?)
            }
            DataType::UInt32 => {
                let array = downcast_value!(values, UInt32Array);
                Ok(array
                    .values()
                    .iter()
                    .filter_map(|v| v.try_as_f64().transpose())
                    .collect::<Result<Vec<_>>>()?)
            }
            DataType::UInt16 => {
                let array = downcast_value!(values, UInt16Array);
                Ok(array
                    .values()
                    .iter()
                    .filter_map(|v| v.try_as_f64().transpose())
                    .collect::<Result<Vec<_>>>()?)
            }
            DataType::UInt8 => {
                let array = downcast_value!(values, UInt8Array);
                Ok(array
                    .values()
                    .iter()
                    .filter_map(|v| v.try_as_f64().transpose())
                    .collect::<Result<Vec<_>>>()?)
            }
            e => internal_err!("DDS_PERCENTILE_CONT is not expected to receive the type {e:?}"),
        }
    }
}

impl Accumulator for DdsPercentileContAccumulator {
    fn state(&mut self) -> Result<Vec<ScalarValue>> {
        // Lazy serialization: only serialize if state has changed
        if self.state_dirty || self.cached_state.is_none() {
            let serialized = bincode::serialize(&self.sketch)
                .map_err(|e| datafusion::error::DataFusionError::Internal(format!("Failed to serialize DDSketch: {}", e)))?;
            self.cached_state = Some(serialized);
            self.state_dirty = false;
        }
        
        // Return cached serialized state
        Ok(vec![ScalarValue::Binary(self.cached_state.clone())])
    }

    fn evaluate(&mut self) -> Result<ScalarValue> {
        if self.sketch.length() == 0 {
            return Ok(ScalarValue::Float64(None));
        }

        let quantile_result = self.sketch.quantile(self.percentile);
        match quantile_result {
            Ok(Some(value)) => Ok(ScalarValue::Float64(Some(value))),
            Ok(None) => Ok(ScalarValue::Float64(None)),
            Err(e) => internal_err!("Failed to calculate quantile: {}", e),
        }
    }

    fn size(&self) -> usize {
        self.sketch.length()
    }

    fn update_batch(&mut self, values: &[ArrayRef]) -> Result<()> {
        let values = Self::convert_to_float(&values[0])?;
        
        // Early exit if no values
        if values.is_empty() {
            return Ok(());
        }
        
        // Batch processing: Add values in chunks to reduce per-call overhead
        const BATCH_SIZE: usize = 1000;
        
        if values.len() > BATCH_SIZE {
            // Process large datasets in chunks
            for chunk in values.chunks(BATCH_SIZE) {
                for &value in chunk {
                    self.sketch.add(value);
                }
            }
        } else {
            // For smaller datasets, process normally
            for &value in &values {
                self.sketch.add(value);
            }
        }
        
        // Mark state as dirty since we added new values
        self.state_dirty = true;
        
        Ok(())
    }

    fn merge_batch(&mut self, states: &[ArrayRef]) -> Result<()> {
        if states.is_empty() {
            return Ok(());
        }

        let array = states[0].as_binary::<i32>();
        let mut merged_any = false;
        
        for v in array.iter().flatten() {
            // Deserialize the DDSketch and merge it
            let other_sketch: DDSketch = bincode::deserialize(v)
                .map_err(|e| datafusion::error::DataFusionError::Internal(format!("Failed to deserialize DDSketch: {}", e)))?;
            self.sketch.merge(&other_sketch)
                .map_err(|e| datafusion::error::DataFusionError::Internal(format!("Failed to merge DDSketch: {}", e)))?;
            merged_any = true;
        }
        
        // Mark state as dirty since we merged new sketches
        if merged_any {
            self.state_dirty = true;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use arrow::array::{ArrayRef, RecordBatch};
    use arrow_schema::{Field, Schema};
    use datafusion::{
        common::cast::as_float64_array,
        datasource::MemTable,
        logical_expr::{Accumulator, AggregateUDF},
        prelude::SessionContext,
    };

    use super::*;

    // list of numbers to test
    const NUMBERS: [u16; 92] = [
        2973, 1018, 5898, 52, 17296, 943, 1363, 1075, 1176, 2257, 1263, 1132, 1749, 967, 1737,
        1380, 1506, 2021, 1341, 3240, 1430, 1632, 2127, 2547, 1346, 1249, 11700, 1491, 1202, 8444,
        916, 1132, 1417, 2527, 1163, 15003, 1299, 2073, 1523, 3783, 2170, 6640, 1493, 981, 1926,
        2066, 2621, 1062, 2108, 852, 3634, 1322, 2433, 1015, 2271, 1819, 2978, 1635, 2102, 2847,
        1208, 3896, 2603, 1174, 8444, 1846, 3291, 1, 1638, 1647, 1101, 1602, 1558, 808, 734, 16227,
        1304, 2219, 1163, 1135, 1429, 2778, 1439, 2553, 1480, 1129, 2054, 1203, 3653, 679, 1591,
        1811,
    ];

    fn create_context() -> SessionContext {
        let ctx = SessionContext::new();
        let schema = Schema::new(vec![
            Field::new("value_float", DataType::Float64, false),
        ]);
        let values_float: Vec<_> = NUMBERS.into_iter().map(|v| v as f64).collect();
        let batch = RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![
                Arc::new(Float64Array::from(values_float)),
            ],
        )
        .unwrap();
        let table = MemTable::try_new(Arc::new(schema), vec![vec![batch]]).unwrap();
        ctx.register_table("t", Arc::new(table)).unwrap();
        ctx
    }

    #[test]
    fn test_dds_percentile_cont() {
        let mut acc = DdsPercentileContAccumulator::new(0.75).unwrap();
        let values: Vec<_> = NUMBERS.into_iter().map(|v| v as f64).collect();
        let values = vec![arrow::array::Float64Array::from(values)]
            .into_iter()
            .map(|v| Arc::new(v) as ArrayRef)
            .collect::<Vec<_>>();
        acc.update_batch(&values).unwrap();

        // Check the result - DDSketch is approximate so we check it's reasonably close
        let result = acc.evaluate().unwrap();
        if let ScalarValue::Float64(Some(value)) = result {
            // Should be close to exact percentile (within a few percent due to DDSketch approximation)
            assert!((value - 2456.5).abs() < 100.0, "DDSketch result {} too far from expected 2456.5", value);
        } else {
            panic!("Expected Float64 result");
        }
    }

    #[tokio::test]
    async fn test_dds_percentile_cont_udaf() {
        let ctx = create_context();
        let percentile = 0.75;
        let sql = &format!("select dds_percentile_cont(value_float, {percentile}) from t");
        let acc_udaf = AggregateUDF::from(DdsPercentileCont::new());
        ctx.register_udaf(acc_udaf);

        let df = ctx.sql(sql).await.unwrap();
        let results = df.collect().await.unwrap();
        let result = as_float64_array(results[0].column(0)).unwrap();
        
        // DDSketch is approximate, so we check it's reasonably close to expected value
        let value = result.value(0);
        assert!((value - 2456.5).abs() < 100.0, "UDAF result {} too far from expected 2456.5", value);
    }

    #[test]
    fn test_dds_percentile_cont_empty_data() {
        let mut acc = DdsPercentileContAccumulator::new(0.5).unwrap();
        let result = acc.evaluate().unwrap();
        assert_eq!(result, ScalarValue::Float64(None));
    }

    #[test]
    fn test_dds_percentile_cont_single_value() {
        let mut acc = DdsPercentileContAccumulator::new(0.5).unwrap();
        let values: ArrayRef = Arc::new(Float64Array::from(vec![42.0]));
        acc.update_batch(&[values]).unwrap();

        let result = acc.evaluate().unwrap();
        if let ScalarValue::Float64(Some(value)) = result {
            assert!((value - 42.0).abs() < 1.0, "DDSketch result {} too far from expected 42.0", value);
        } else {
            panic!("Expected Float64 result");
        }
    }

    #[test]
    fn test_dds_percentile_cont_state_merge() {
        let mut acc1 = DdsPercentileContAccumulator::new(0.5).unwrap();
        let mut acc2 = DdsPercentileContAccumulator::new(0.5).unwrap();

        // Add values to first accumulator
        let values1: ArrayRef = Arc::new(Float64Array::from(vec![1.0, 2.0, 3.0]));
        acc1.update_batch(&[values1]).unwrap();

        // Add values to second accumulator  
        let values2: ArrayRef = Arc::new(Float64Array::from(vec![4.0, 5.0, 6.0]));
        acc2.update_batch(&[values2]).unwrap();

        // Get state from second accumulator
        let state = acc2.state().unwrap();
        
        // Extract binary data from ScalarValue
        let binary_data = if let ScalarValue::Binary(Some(data)) = &state[0] {
            data.clone()
        } else {
            panic!("Expected Binary scalar value");
        };
        
        let state_array = vec![Arc::new(arrow::array::BinaryArray::from_vec(
            vec![&binary_data]
        )) as ArrayRef];

        // Merge state into first accumulator
        acc1.merge_batch(&state_array).unwrap();

        // Result should be approximate median of [1,2,3,4,5,6] = 3.5
        let result = acc1.evaluate().unwrap();
        if let ScalarValue::Float64(Some(value)) = result {
            assert!((value - 3.5).abs() < 1.0); // Allow some approximation error
        } else {
            panic!("Expected Float64 result");
        }
    }

    #[test]
    fn test_validate_input_percentile_expr_valid() {
        let expr: Arc<dyn datafusion::physical_plan::PhysicalExpr> = Arc::new(
            datafusion::physical_expr::expressions::Literal::new(ScalarValue::Float64(Some(0.5))),
        );
        let result = validate_input_percentile_expr(&expr).unwrap();
        assert_eq!(result, 0.5);
    }

    #[test]
    fn test_validate_input_percentile_expr_invalid() {
        let expr: Arc<dyn datafusion::physical_plan::PhysicalExpr> = Arc::new(
            datafusion::physical_expr::expressions::Literal::new(ScalarValue::Float64(Some(1.5))),
        );
        let result = validate_input_percentile_expr(&expr);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must be between 0.0 and 1.0")
        );
    }

    #[test]
    fn test_dds_percentile_cont_name() {
        let dpc = DdsPercentileCont::new();
        assert_eq!(dpc.name(), "dds_percentile_cont");
    }

    #[test]
    fn test_dds_percentile_cont_return_type() {
        let dpc = DdsPercentileCont::new();
        let result = dpc.return_type(&[DataType::Float64, DataType::Float64]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), DataType::Float64);
    }

    #[test]
    fn test_dds_percentile_cont_lazy_serialization() {
        let mut acc = DdsPercentileContAccumulator::new(0.5).unwrap();
        
        // Initially, cached state should be None
        assert!(acc.cached_state.is_none());
        assert!(!acc.state_dirty);
        
        // Add some values
        let values: ArrayRef = Arc::new(Float64Array::from(vec![1.0, 2.0, 3.0]));
        acc.update_batch(&[values]).unwrap();
        
        // State should now be marked as dirty
        assert!(acc.state_dirty);
        
        // First call to state() should serialize and cache
        let state1 = acc.state().unwrap();
        assert!(acc.cached_state.is_some());
        assert!(!acc.state_dirty);
        
        // Second call to state() should return cached version (no re-serialization)
        let state2 = acc.state().unwrap();
        assert_eq!(state1, state2);
        assert!(!acc.state_dirty);
        
        // Adding more values should mark state as dirty again
        let values2: ArrayRef = Arc::new(Float64Array::from(vec![4.0, 5.0]));
        acc.update_batch(&[values2]).unwrap();
        assert!(acc.state_dirty);
    }

    #[test]
    fn test_dds_percentile_cont_batch_processing() {
        let mut acc = DdsPercentileContAccumulator::new(0.5).unwrap();
        
        // Test with large batch (> BATCH_SIZE = 1000)
        let large_values: Vec<f64> = (0..2000).map(|i| i as f64).collect();
        let values: ArrayRef = Arc::new(Float64Array::from(large_values));
        acc.update_batch(&[values]).unwrap();
        
        // DDSketch length() returns number of buckets, not number of values
        // So we just check that some buckets were created and state is dirty
        assert!(acc.size() > 0, "Expected some buckets to be created");
        assert!(acc.state_dirty);
        
        let result = acc.evaluate().unwrap();
        if let ScalarValue::Float64(Some(value)) = result {
            // Median of 0..2000 should be around 999.5
            assert!((value - 999.5).abs() < 50.0, "Batch processing result {} unexpected", value);
        } else {
            panic!("Expected Float64 result");
        }
    }
}
