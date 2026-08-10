import { Agent } from '@mastra/core/agent';
import type { AgentConfig } from '@mastra/core/agent';
import type {
  AgentBuilderOptions,
  BuilderAgentConfiguration,
  BuilderAgentFeatures,
  BuilderModelPolicy,
  BuilderProviderModelEntry,
  IAgentBuilder,
} from '@mastra/core/editor';
import { PROVIDER_REGISTRY } from '@mastra/core/llm';
import type { IMastraLogger } from '@mastra/core/logger';
import { PrefillErrorHandler, ProviderHistoryCompat, StreamErrorRetryProcessor } from '@mastra/core/processors';
import type { ErrorProcessorOrWorkflow } from '@mastra/core/processors';
import type { StorageCreateAgentInput } from '@mastra/core/storage';

const BUILDER_AGENT_ID = 'builder-agent';
const BUILDER_AGENT_NAME = 'Builder Agent';
const BUILDER_AGENT_DESCRIPTION = 'Helps create and configure Mastra agents.';

const BUILDER_AGENT_INSTRUCTIONS = `You help users configure a Mastra agent.
Use the available configuration tools to apply requested changes. Treat the current agent configuration supplied with each request as authoritative. Ask a concise follow-up only when a required choice is missing, and do not claim a change was made unless the matching tool succeeded.`;

const DEFAULT_AGENT_OPTIONS = {
  providerOptions: {
    openai: { reasoningEffort: 'low' as const },
  },
};

export const BUILDER_BASELINE_DEFAULTS: BuilderAgentConfiguration = {
  memory: {
    observationalMemory: { model: 'openai/gpt-5-mini' },
  },
};

const FEATURE_KEYS = [
  'tools',
  'agents',
  'workflows',
  'scorers',
  'skills',
  'memory',
  'variables',
  'favorites',
  'avatarUpload',
  'browser',
  'model',
] as const satisfies readonly (keyof BuilderAgentFeatures)[];

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function mergeValues(base: unknown, override: unknown): unknown {
  if (override === undefined) return base;
  if (!isPlainObject(base) || !isPlainObject(override)) return override;

  const result: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(override)) {
    result[key] = mergeValues(result[key], value);
  }
  return result;
}

function mergeRecords<T>(...records: Array<object | undefined>): T {
  return records.reduce<Record<string, unknown>>(
    (result, record) =>
      record ? (mergeValues(result, record as Record<string, unknown>) as Record<string, unknown>) : result,
    {},
  ) as T;
}

function normalizeProvider(provider: string): string {
  return provider.endsWith('.chat') ? provider.slice(0, -'.chat'.length) : provider;
}

function providersMatch(modelProvider: string, configuredProvider: string): boolean {
  const model = normalizeProvider(modelProvider);
  const configured = normalizeProvider(configuredProvider);
  if (model === configured) return true;
  if (configured.includes('/')) return false;

  const parts = model.split('/');
  return parts.length === 2 && parts[1] === configured;
}

export function isModelAllowed(
  allowed: BuilderProviderModelEntry[] | undefined,
  model: { provider: string; modelId?: string },
): boolean {
  if (!allowed?.length) return true;
  return allowed.some(entry => {
    if (!providersMatch(model.provider, entry.provider)) return false;
    return entry.modelId === undefined || entry.modelId === model.modelId;
  });
}

function validateModelEntry(entry: BuilderProviderModelEntry, label: string, requireModel = false): void {
  if (!entry || typeof entry !== 'object' || typeof entry.provider !== 'string' || entry.provider.trim() === '') {
    throw new TypeError(`${label} must include a non-empty provider`);
  }
  if (requireModel && (typeof entry.modelId !== 'string' || entry.modelId.trim() === '')) {
    throw new TypeError(`${label} must include a non-empty modelId`);
  }
  if (entry.modelId !== undefined && (typeof entry.modelId !== 'string' || entry.modelId.trim() === '')) {
    throw new TypeError(`${label}.modelId must be a non-empty string when provided`);
  }
  if (entry.kind !== undefined && entry.kind !== 'custom') {
    throw new TypeError(`${label}.kind must be "custom" when provided`);
  }
}

function knownProvider(provider: string): boolean {
  const normalized = normalizeProvider(provider);
  if (normalized in PROVIDER_REGISTRY) return true;
  if (normalized.includes('/')) return false;
  return Object.keys(PROVIDER_REGISTRY).some(id => id.split('/').length === 2 && id.split('/')[1] === normalized);
}

function validateModels(
  configuration: BuilderAgentConfiguration,
  features: BuilderAgentFeatures,
): { warnings: string[] } {
  const models = configuration.models;
  if (!models) {
    if (!features.model) {
      throw new Error(
        'Builder model picker is hidden, so configuration.agent.models.default must specify a default model',
      );
    }
    return { warnings: [] };
  }

  const warnings: string[] = [];
  const entries: Array<{ entry: BuilderProviderModelEntry; label: string; requireModel?: boolean }> = [
    ...(models.allowed ?? []).map((entry, index) => ({ entry, label: `configuration.agent.models.allowed[${index}]` })),
    ...(models.default
      ? [{ entry: models.default, label: 'configuration.agent.models.default', requireModel: true }]
      : []),
  ];

  for (const { entry, label, requireModel } of entries) {
    validateModelEntry(entry, label, requireModel);
    if (entry.kind !== 'custom' && !knownProvider(entry.provider)) {
      warnings.push(`${label} uses unknown provider "${entry.provider}"; mark it with kind: "custom" if intentional.`);
    }
  }

  if (!features.model && !models.default) {
    throw new Error(
      'Builder model picker is hidden, so configuration.agent.models.default must specify a default model',
    );
  }
  if (models.default && !isModelAllowed(models.allowed, models.default)) {
    throw new Error('Builder default model must be included in configuration.agent.models.allowed');
  }

  return { warnings: [...new Set(warnings)] };
}

function resolveFeatures(
  options: AgentBuilderOptions,
  configuration: BuilderAgentConfiguration,
  logger?: IMastraLogger,
): BuilderAgentFeatures {
  const configured = options.features?.agent ?? {};
  const resolved = Object.fromEntries(
    FEATURE_KEYS.map(key => [key, configured[key] ?? true]),
  ) as unknown as BuilderAgentFeatures;
  const hasBrowser = Boolean(configuration.browser);

  if (configured.browser === true && !hasBrowser) {
    logger?.warn(
      '[mastra:editor] Agent Builder browser feature was enabled without configuration.agent.browser; hiding browser controls.',
    );
    resolved.browser = false;
  } else if (configured.browser === undefined) {
    resolved.browser = hasBrowser;
  }

  return resolved;
}

export class EditorAgentBuilder implements IAgentBuilder {
  readonly enabled: boolean;
  readonly #features: { agent: BuilderAgentFeatures };
  readonly #configuration: { agent: BuilderAgentConfiguration };
  readonly #registries: NonNullable<AgentBuilderOptions['registries']>;
  readonly #warnings: string[];

  constructor(options: AgentBuilderOptions, logger?: IMastraLogger) {
    this.enabled = options.enabled === true;
    const agentConfiguration = mergeRecords<BuilderAgentConfiguration>(
      BUILDER_BASELINE_DEFAULTS,
      options.configuration?.agent,
    );
    const agentFeatures = resolveFeatures(options, agentConfiguration, logger);
    const { warnings } = validateModels(agentConfiguration, agentFeatures);

    this.#features = { agent: agentFeatures };
    this.#configuration = { agent: agentConfiguration };
    this.#registries = options.registries ?? {};
    this.#warnings = warnings;
  }

  getFeatures(): { agent: BuilderAgentFeatures } {
    return this.#features;
  }

  getConfiguration(): { agent: BuilderAgentConfiguration } {
    return this.#configuration;
  }

  getRegistries(): NonNullable<AgentBuilderOptions['registries']> {
    return this.#registries;
  }

  getModelPolicyWarnings(): string[] {
    return [...this.#warnings];
  }
}

export function builderToModelPolicy(builder: IAgentBuilder | undefined): BuilderModelPolicy {
  if (!builder?.enabled) return { active: false };
  const models = builder.getConfiguration().agent?.models;
  if (!models) return { active: false };

  return {
    active: true,
    pickerVisible: builder.getFeatures().agent.model !== false,
    ...(models.allowed !== undefined ? { allowed: models.allowed } : {}),
    ...(models.default !== undefined ? { default: models.default } : {}),
  };
}

export interface ResolvePickerVisibilityOptions {
  config?: Pick<BuilderAgentConfiguration, 'tools' | 'agents' | 'workflows'>;
  registeredToolIds?: string[];
  registeredAgentIds?: string[];
  registeredWorkflowIds?: string[];
}

export interface BuilderPickerVisibility {
  visibleTools: string[] | null;
  visibleAgents: string[] | null;
  visibleWorkflows: string[] | null;
  warnings: string[];
}

function resolveAllowedIds(
  kind: 'tools' | 'agents' | 'workflows',
  allowed: string[] | undefined,
  registered: string[],
  warnings: string[],
): string[] | null {
  if (allowed === undefined) return null;
  const registeredSet = new Set(registered);
  const visible: string[] = [];
  const seen = new Set<string>();

  for (const id of allowed) {
    if (!registeredSet.has(id)) {
      warnings.push(`Builder ${kind} allowlist references unknown id "${id}".`);
    } else if (!seen.has(id)) {
      seen.add(id);
      visible.push(id);
    }
  }
  return visible;
}

export function resolvePickerVisibility(options: ResolvePickerVisibilityOptions): BuilderPickerVisibility {
  const warnings: string[] = [];
  return {
    visibleTools: resolveAllowedIds('tools', options.config?.tools?.allowed, options.registeredToolIds ?? [], warnings),
    visibleAgents: resolveAllowedIds(
      'agents',
      options.config?.agents?.allowed,
      options.registeredAgentIds ?? [],
      warnings,
    ),
    visibleWorkflows: resolveAllowedIds(
      'workflows',
      options.config?.workflows?.allowed,
      options.registeredWorkflowIds ?? [],
      warnings,
    ),
    warnings,
  };
}

function createDefaultErrorProcessors(): ErrorProcessorOrWorkflow[] {
  return [new StreamErrorRetryProcessor(), new PrefillErrorHandler(), new ProviderHistoryCompat()];
}

function mergeErrorProcessors(
  defaults: ErrorProcessorOrWorkflow[],
  configured: ErrorProcessorOrWorkflow[],
): ErrorProcessorOrWorkflow[] {
  if (configured.length === 0) return [];
  const merged = [...defaults];
  const indexById = new Map(merged.map((processor, index) => [processor.id, index]));

  for (const processor of configured) {
    const index = indexById.get(processor.id);
    if (index === undefined) {
      indexById.set(processor.id, merged.length);
      merged.push(processor);
    } else {
      merged[index] = processor;
    }
  }
  return merged;
}

export type CreateBuilderAgentConfig = Partial<Omit<AgentConfig, 'id' | 'name' | 'description'>>;

export function createBuilderAgent(config: CreateBuilderAgentConfig = {}): Agent {
  const defaults = createDefaultErrorProcessors();
  const configuredErrorProcessors = config.errorProcessors;
  const errorProcessors =
    configuredErrorProcessors === undefined
      ? defaults
      : typeof configuredErrorProcessors === 'function'
        ? async (args: Parameters<typeof configuredErrorProcessors>[0]) =>
            mergeErrorProcessors(defaults, await configuredErrorProcessors(args))
        : mergeErrorProcessors(defaults, configuredErrorProcessors);

  const configuredDefaultOptions = config.defaultOptions;
  const defaultOptions =
    typeof configuredDefaultOptions === 'function'
      ? async (args: Parameters<typeof configuredDefaultOptions>[0]) =>
          mergeRecords(DEFAULT_AGENT_OPTIONS, await configuredDefaultOptions(args))
      : mergeRecords(DEFAULT_AGENT_OPTIONS, configuredDefaultOptions);

  return new Agent({
    model: 'openai/gpt-5',
    instructions: BUILDER_AGENT_INSTRUCTIONS,
    ...config,
    defaultOptions,
    errorProcessors,
    id: BUILDER_AGENT_ID,
    name: BUILDER_AGENT_NAME,
    description: BUILDER_AGENT_DESCRIPTION,
  } as AgentConfig);
}

const AGENT_POLICY_FIELDS = new Set(['models', 'tools', 'agents', 'workflows']);

function agentDefaults(configuration: BuilderAgentConfiguration | undefined): Record<string, unknown> {
  if (!configuration) return {};
  return Object.fromEntries(Object.entries(configuration).filter(([key]) => !AGENT_POLICY_FIELDS.has(key)));
}

/** Apply portable defaults first and administrator-pinned defaults last. */
export function applyBuilderAgentDefaults(
  input: StorageCreateAgentInput,
  configuration: BuilderAgentConfiguration | undefined,
): StorageCreateAgentInput {
  return mergeRecords<StorageCreateAgentInput>(BUILDER_BASELINE_DEFAULTS, input, agentDefaults(configuration));
}
