/**
 * @license
 * Copyright 2022-2024 Matter.js Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import { DecodedMessage, DecodedPacket, Message, Packet } from "../codec/MessageCodec.js";
import { NodeId } from "../datatype/NodeId.js";
import { Fabric } from "../fabric/Fabric.js";
import { MessageCounter } from "../protocol/MessageCounter.js";
import { MessageReceptionState } from "../protocol/MessageReceptionState.js";
import { Time } from "../time/Time.js";
import { ByteArray } from "../util/ByteArray.js";

/**
 * Minimum amount of time between sender retries when the destination node is Active. This SHALL be greater than or
 * equal to the maximum amount of time a node may be non-responsive to incoming messages when Active.
 */
export const SESSION_ACTIVE_INTERVAL_MS = 300;

/**
 * Minimum amount of time between sender retries when the destination node is Idle. This SHALL be greater than or equal
 * to the maximum amount of time a node may be non-responsive to incoming messages when Idle.
 */
export const SESSION_IDLE_INTERVAL_MS = 500;

/** Minimum amount of time the node SHOULD stay active after network activity. */
export const SESSION_ACTIVE_THRESHOLD_MS = 4000;

/** Fallback value for Data Model Revision when not provided in Session parameters. We use Matter 1.2 as assumption. */
export const FALLBACK_DATAMODEL_REVISION = 17;

/** Fallback value for Interaction Model Revision when not provided in Session parameters. We use Matter 1.2 as assumption. */
export const FALLBACK_INTERACTIONMODEL_REVISION = 11;

/**
 * Fallback value for Specification Version when not provided in Session parameters. We use 0 as assumption which is
 * "before 1.3".
 */
export const FALLBACK_SPECIFICATION_VERSION = 0;

/**
 * Fallback value for Maximum Paths per Invoke when not provided in Session parameters. We assume only one Path is
 * supported per Invoke interaction.
 */
export const FALLBACK_MAX_PATHS_PER_INVOKE = 1;

export interface SessionParameters {
    idleIntervalMs: number;
    activeIntervalMs: number;
    activeThresholdMs: number;
    dataModelRevision: number;
    interactionModelRevision: number;
    specificationVersion: number;
    maxPathsPerInvoke: number;
}

export type SessionParameterOptions = Partial<SessionParameters>;

export abstract class Session<T> {
    abstract get name(): string;
    abstract get closingAfterExchangeFinished(): boolean;
    timestamp = Time.nowMs();
    activeTimestamp = 0;
    protected readonly idleIntervalMs: number;
    protected readonly activeIntervalMs: number;
    protected readonly activeThresholdMs: number;
    protected readonly dataModelRevision: number;
    protected readonly interactionModelRevision: number;
    protected readonly specificationVersion: number;
    protected readonly maxPathsPerInvoke: number;
    protected readonly closeCallback: () => Promise<void>;
    protected readonly messageCounter: MessageCounter;
    protected readonly messageReceptionState: MessageReceptionState;

    constructor(args: {
        messageCounter: MessageCounter;
        messageReceptionState: MessageReceptionState;
        closeCallback: () => Promise<void>;
        sessionParameters?: SessionParameterOptions;
        setActiveTimestamp: boolean;
    }) {
        const {
            messageCounter,
            messageReceptionState,
            closeCallback,
            sessionParameters: {
                idleIntervalMs = SESSION_IDLE_INTERVAL_MS,
                activeIntervalMs = SESSION_ACTIVE_INTERVAL_MS,
                activeThresholdMs = SESSION_ACTIVE_THRESHOLD_MS,
                dataModelRevision = FALLBACK_DATAMODEL_REVISION,
                interactionModelRevision = FALLBACK_INTERACTIONMODEL_REVISION,
                specificationVersion = FALLBACK_SPECIFICATION_VERSION,
                maxPathsPerInvoke = FALLBACK_MAX_PATHS_PER_INVOKE,
            } = {},
            setActiveTimestamp,
        } = args;
        this.messageCounter = messageCounter;
        this.messageReceptionState = messageReceptionState;
        this.closeCallback = closeCallback;
        this.idleIntervalMs = idleIntervalMs;
        this.activeIntervalMs = activeIntervalMs;
        this.activeThresholdMs = activeThresholdMs;
        this.dataModelRevision = dataModelRevision;
        this.interactionModelRevision = interactionModelRevision;
        this.specificationVersion = specificationVersion;
        this.maxPathsPerInvoke = maxPathsPerInvoke;
        if (setActiveTimestamp) {
            this.activeTimestamp = this.timestamp;
        }
    }

    notifyActivity(messageReceived: boolean) {
        this.timestamp = Time.nowMs();
        if (messageReceived) {
            // only update active timestamp if we received a message
            this.activeTimestamp = this.timestamp;
        }
    }

    isPeerActive(): boolean {
        return Time.nowMs() - this.activeTimestamp < this.activeThresholdMs;
    }

    getIncrementedMessageCounter() {
        return this.messageCounter.getIncrementedCounter();
    }

    updateMessageCounter(messageCounter: number, _sourceNodeId?: NodeId) {
        this.messageReceptionState.updateMessageCounter(messageCounter);
    }

    get parameters(): SessionParameters {
        const {
            idleIntervalMs,
            activeIntervalMs,
            activeThresholdMs,
            dataModelRevision,
            interactionModelRevision,
            specificationVersion,
            maxPathsPerInvoke,
        } = this;
        return {
            idleIntervalMs,
            activeIntervalMs,
            activeThresholdMs,
            dataModelRevision,
            interactionModelRevision,
            specificationVersion,
            maxPathsPerInvoke,
        };
    }

    abstract isSecure: boolean;
    abstract isPase: boolean;
    abstract context: T;
    abstract id: number;
    abstract peerSessionId: number;
    abstract nodeId: NodeId | undefined;
    abstract peerNodeId: NodeId | undefined;
    abstract associatedFabric: Fabric;

    abstract decode(packet: DecodedPacket, aad?: ByteArray): DecodedMessage;
    abstract encode(message: Message): Packet;
    abstract end(sendClose: boolean): Promise<void>;
    abstract destroy(sendClose?: boolean, closeAfterExchangeFinished?: boolean): Promise<void>;
}
