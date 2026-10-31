<!-- Modifications Copyright (C) 2026 Mike Sauh -->
<template>
  <div class="flex h-screen">
    <!-- Left Brand Panel -->
    <div
      class="bg-surface-secondary hidden flex-col items-center justify-center gap-6 lg:flex lg:w-[40%]"
    >
      <img
        class="h-24"
        :src="isDark ? getImageURL(config.logoDark) : getImageURL(config.logoLight)"
        :alt="t('login.openObserveLogoAlt')"
      />
      <p class="text-text-secondary max-w-80 px-8 text-center text-2xl leading-8.25 font-semibold">
        {{ t("login.getStartedBannerMessage") }}
      </p>
    </div>

    <!-- Right Form Section -->
    <div
      class="bg-surface-base relative flex h-full w-full flex-col items-center justify-center lg:w-[60%]"
    >
      <!-- Top Section: Logo and Heading -->
      <div class="mb-4 flex flex-col items-center">
        <img
          class="h-16"
          :src="isDark ? getImageURL(config.logoDark) : getImageURL(config.logoLight)"
          :alt="t('login.getStartedBannerAlt')"
        />
        <div class="text-text-heading text-center text-2xl font-semibold md:text-3xl">
          {{ t("login.getStartedHeading") }}
        </div>
      </div>

      <!-- Form Section -->
      <!-- Form Section -->
      <div class="flex w-full justify-center">
        <div class="flex w-full max-w-125 flex-col items-center gap-y-2 px-4">
          <OForm
            ref="formRef"
            :schema="getStartedSchema"
            :default-values="getStartedDefaults()"
            @submit="doSubmit"
            v-slot="{ isSubmitting }"
            class="flex w-full flex-col gap-y-2"
          >
            <OFormInput
              name="hearAboutUs"
              data-test="onboarding-get-started-hear-about-us"
              class="o2-input w-full"
              :label="t('login.hearAboutUsLabel')"
              required
              :placeholder="t('login.hearAboutUsPlaceholder')"
            />
            <OFormInput
              name="whereDoYouWork"
              data-test="onboarding-get-started-where-do-you-work"
              class="-mt-2 w-full"
              :label="t('login.whereDoYouWorkLabel')"
              required
              :placeholder="t('login.whereDoYouWorkPlaceholder')"
            />
            <div class="w-full">
              <OFormCheckbox name="isAgree" data-test="onboarding-get-started-agree-checkbox">
                <template #label>
                  <span class="text-sm">
                    {{ t("login.agreeToTermsPrefix") }}
                    <a
                      href="https://github.com/ExposedObserve/ExposedObserve/blob/master/LICENSE"
                      target="_blank"
                      rel="noopener"
                      class="text-text-link hover:underline"
                      data-test="onboarding-get-started-terms-link"
                      >{{ t("login.termsOfUse") }}</a
                    >
                    {{ t("login.and") }}
                    <a
                      href="https://github.com/ExposedObserve/ExposedObserve/blob/master/SECURITY.md"
                      target="_blank"
                      rel="noopener"
                      class="text-text-link hover:underline"
                      data-test="onboarding-get-started-privacy-link"
                      >{{ t("login.privacyPolicyStar") }}</a
                    >
                  </span>
                </template>
              </OFormCheckbox>
            </div>
            <div class="mt-4 w-full">
              <OButton
                data-test="onboarding-get-started-submit-btn"
                variant="primary"
                size="md"
                block
                :disabled="isSubmitting"
                :loading="isSubmitting"
                type="submit"
              >
                {{ t("login.startTrialButton") }}
              </OButton>
            </div>
          </OForm>
        </div>
      </div>

      <!-- Footer -->
      <div class="text-text-secondary absolute bottom-5 mb-4 text-sm">
        {{ t("login.copyrightNotice") }} {{ config.appName }}
        <span id="year">{{ new Date().getFullYear() }}</span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from "vue";
import OButton from "@/lib/core/Button/OButton.vue";
import OForm from "@/lib/forms/Form/OForm.vue";
import OFormInput from "@/lib/forms/Input/OFormInput.vue";
import OFormCheckbox from "@/lib/forms/Checkbox/OFormCheckbox.vue";
import { makeGetStartedSchema, getStartedDefaults, type GetStartedForm } from "./GetStarted.schema";
import { useStore } from "vuex";
import billings from "@/services/billings";
import config from "@/aws-exports";
import { useTheme } from "@/composables/useTheme";
import { getImageURL } from "@/utils/zincutils";
import { toast } from "@/lib/feedback/Toast/useToast";
import { useI18nTyped } from "@/types/i18n";
const store = useStore();
const { t } = useI18nTyped();
const { isDark } = useTheme();

const getStartedSchema = makeGetStartedSchema(t);
const emit = defineEmits(["removeFirstTimeLogin"]);
const formRef = ref(null);

const doSubmit = async (value: GetStartedForm) => {
  const res = await billings.submit_new_user_info(store.state.selectedOrganization.identifier, {
    from: value.hearAboutUs,
    company: value.whereDoYouWork,
  });
  if (res.status == 200) {
    localStorage.removeItem("isFirstTimeLogin");
    emit("removeFirstTimeLogin", false);
    // Notify first-login follow-ups (e.g. the community Slack invite) that the
    // onboarding form is done, so they don't stack on top of this full-screen dialog.
    window.dispatchEvent(new CustomEvent("o2:onboarding-complete"));
    toast({
      message: t("toastMessages.login.thankYouForYourFeedback"),
      variant: "success",
    });
  } else {
    toast({
      message: t("toastMessages.login.somethingWentWrong"),
      variant: "error",
    });
  }
};
</script>
