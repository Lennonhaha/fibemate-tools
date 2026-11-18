// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 FIBEMATE Contributors
//
// Negative control for test/legacy-recall.test.cjs: ordinary English that
// shares a word with an algorithm name. `cross`, `bike` and `mayo` are real
// words, so the scanner deliberately requires a parameter context for them.
// If any of them starts producing a component, the rules became too broad and
// a reviewer would be reading crypto that is not there.

const route = 'cross the road at the lights';
const lane = 'the bike lane is closed';
const lunch = 'mayo on a sandwich, no crypto involved';

module.exports = { route, lane, lunch };
