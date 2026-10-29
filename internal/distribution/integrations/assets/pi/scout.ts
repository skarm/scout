// SPDX-License-Identifier: Apache-2.0
import type { ExtensionAPI } from '@earendil-works/pi-coding-agent';
import { Type } from 'typebox';
import { registerPi } from './lib/adapters.mjs';

export default function (pi: ExtensionAPI) {
  registerPi(pi, Type);
}
