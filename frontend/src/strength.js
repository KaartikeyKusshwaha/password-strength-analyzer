import { ZxcvbnFactory } from "@zxcvbn-ts/core";
import * as common from "@zxcvbn-ts/language-common";
import * as en from "@zxcvbn-ts/language-en";
export const estimator = new ZxcvbnFactory({
  translations: en.translations,
  graphs: common.adjacencyGraphs,
  dictionary: { ...common.dictionary, ...en.dictionary },
});
