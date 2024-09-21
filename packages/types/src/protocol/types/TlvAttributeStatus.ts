/**
 * @license
 * Copyright 2022-2024 Matter.js Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import { TlvField, TlvObject } from "../../tlv/TlvObject.js";
import { TlvAttributePath } from "./TlvAttributePath.js";
import { TlvStatus } from "./TlvStatus.js";

/** @see {@link MatterSpecification.v13.Core}, section 10.6.16 */

export const TlvAttributeStatus = TlvObject({
    // AttributeStatusIB
    path: TlvField(0, TlvAttributePath),
    status: TlvField(1, TlvStatus),
});