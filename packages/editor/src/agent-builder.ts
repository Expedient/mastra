import { Memory } from '@mastra/memory';
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
import type { StorageCreateAgentInput, StorageModelConfig } from '@mastra/core/storage';

const BUILDER_AGENT_ID = 'builder-agent';
const BUILDER_AGENT_NAME = 'Agent Builder';
const BUILDER_AGENT_DESCRIPTION = 'Helps create and configure Mastra agents.';
const BUILDER_AGENT_MODEL = 'openai/gpt-5.6-sol';
const BUILDER_OBSERVATIONAL_MEMORY_MODEL = 'openai/gpt-5.4-mini';

const BUILDER_AGENT_INSTRUCTIONS = `You help users configure a Mastra agent.
Use the available configuration tools to apply requested changes. Treat the current agent configuration supplied with each request as authoritative. Ask a concise follow-up only when a required choice is missing, and do not claim a change was made unless the matching tool succeeded.`;

const DEFAULT_AGENT_OPTIONS = {
  providerOptions: {
    openai: { reasoningEffort: 'low' as const },
  },
};

export const BUILDER_BASELINE_DEFAULTS: BuilderAgentConfiguration = {
  memory: {
    observationalMemory: { model: BUILDER_OBSERVATIONAL_MEMORY_MODEL },
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

const TRUSTED_PROVIDER_ALIASES: Readonly<Record<string, string>> = {
  'openai.chat': 'openai',
};

function normalizeProvider(provider: string): string {
  return TRUSTED_PROVIDER_ALIASES[provider] ?? provider;
}

function providersMatch(modelProvider: string, configuredProvider: string): boolean {
  return normalizeProvider(modelProvider) === normalizeProvider(configuredProvider);
}

export function isModelAllowed(
  allowed: BuilderProviderModelEntry[] | undefined,
  model: { provider: string; modelId?: string },
): boolean {
  if (allowed === undefined) return true;
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
  return normalizeProvider(provider) in PROVIDER_REGISTRY;
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
  browserProviders: ReadonlyMap<string, unknown>,
): { features: BuilderAgentFeatures; warnings: string[] } {
  const configured = options.features?.agent ?? {};
  const features = Object.fromEntries(
    FEATURE_KEYS.map(key => [key, configured[key] ?? true]),
  ) as unknown as BuilderAgentFeatures;
  const warnings: string[] = [];
  const browser = configuration.browser as unknown;

  let browserProvider: string | undefined;
  if (
    isPlainObject(browser) &&
    browser.type === 'inline' &&
    isPlainObject(browser.config) &&
    typeof browser.config.provider === 'string' &&
    browser.config.provider.trim() !== ''
  ) {
    browserProvider = browser.config.provider;
  }

  if (browser !== undefined && browserProvider === undefined) {
    warnings.push(
      'configuration.agent.browser must be an inline browser config with a non-empty provider; hiding browser controls.',
    );
    features.browser = false;
  } else if (browserProvider !== undefined && !browserProviders.has(browserProvider)) {
    warnings.push(
      `configuration.agent.browser uses unregistered provider "${browserProvider}"; hiding browser controls.`,
    );
    features.browser = false;
  } else if (browserProvider === undefined) {
    if (configured.browser === true) {
      warnings.push(
        'Agent Builder browser feature was enabled without configuration.agent.browser; hiding browser controls.',
      );
    }
    features.browser = false;
  }

  return { features, warnings };
}

export class EditorAgentBuilder implements IAgentBuilder {
  readonly enabled: boolean;
  readonly #features: { agent: BuilderAgentFeatures };
  readonly #configuration: { agent: BuilderAgentConfiguration };
  readonly #registries: NonNullable<AgentBuilderOptions['registries']>;
  readonly #warnings: string[];

  constructor(
    options: AgentBuilderOptions,
    logger?: IMastraLogger,
    browserProviders: ReadonlyMap<string, unknown> = new Map(),
  ) {
    this.enabled = options.enabled !== false;
    const agentConfiguration = mergeRecords<BuilderAgentConfiguration>(
      BUILDER_BASELINE_DEFAULTS,
      options.configuration?.agent,
    );
    const { features: agentFeatures, warnings: featureWarnings } = resolveFeatures(
      options,
      agentConfiguration,
      browserProviders,
    );
    const { warnings: modelWarnings } = validateModels(agentConfiguration, agentFeatures);
    const warnings = [...new Set([...featureWarnings, ...modelWarnings])];
    for (const warning of warnings) {
      logger?.warn(`[mastra:editor] ${warning}`);
    }

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

  return {
    active: true,
    pickerVisible: builder.getFeatures().agent.model !== false,
    ...(models?.allowed !== undefined ? { allowed: models.allowed } : {}),
    ...(models?.default !== undefined ? { default: models.default } : {}),
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

export type CreateBuilderAgentConfig = Partial<Omit<AgentConfig, 'id' | 'name' | 'description'>>;

export function createBuilderAgent(config: CreateBuilderAgentConfig = {}): Agent {
  const errorProcessors = config.errorProcessors ?? createDefaultErrorProcessors();
  const memory =
    config.memory === undefined
      ? new Memory({ options: { observationalMemory: { model: BUILDER_OBSERVATIONAL_MEMORY_MODEL } } })
      : config.memory;

  const configuredDefaultOptions = config.defaultOptions;
  const defaultOptions =
    typeof configuredDefaultOptions === 'function'
      ? async (args: Parameters<typeof configuredDefaultOptions>[0]) =>
          mergeRecords(DEFAULT_AGENT_OPTIONS, await configuredDefaultOptions(args))
      : mergeRecords(DEFAULT_AGENT_OPTIONS, configuredDefaultOptions);

  return new Agent({
    model: BUILDER_AGENT_MODEL,
    instructions: BUILDER_AGENT_INSTRUCTIONS,
    ...config,
    memory,
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

function toStorageModelConfig(
  model: NonNullable<NonNullable<BuilderAgentConfiguration['models']>['default']>,
): StorageModelConfig {
  return { provider: model.provider, name: model.modelId };
}

/** Apply portable defaults first and administrator-pinned defaults last. */
export function applyBuilderAgentDefaults(
  input: StorageCreateAgentInput,
  configuration: BuilderAgentConfiguration | undefined,
): StorageCreateAgentInput {
  const resolved = mergeRecords<StorageCreateAgentInput>(
    BUILDER_BASELINE_DEFAULTS,
    input,
    agentDefaults(configuration),
  );
  if (input.model === undefined && configuration?.models?.default) {
    resolved.model = toStorageModelConfig(configuration.models.default);
  }
  return resolved;
}

function storedModels(model: StorageCreateAgentInput['model']): StorageModelConfig[] {
  if (Array.isArray(model)) {
    return model.map(variant => variant.value);
  }
  return model ? [model] : [];
}

function createModelNotAllowedError(
  message: string,
  allowed: BuilderProviderModelEntry[],
  attempted: { provider: string; modelId?: string },
): Error {
  return Object.assign(new Error(message), {
    code: 'MODEL_NOT_ALLOWED' as const,
    allowed,
    attempted,
    offendingLabel: 'model',
  });
}

/** Enforce administrator model allowlists and locked model selection for direct SDK creates. */
export function assertBuilderAgentModelPolicy(
  input: StorageCreateAgentInput,
  configuration: BuilderAgentConfiguration | undefined,
  features: Pick<Partial<BuilderAgentFeatures>, 'model'>,
): void {
  const models = configuration?.models;
  if (!models) return;

  for (const model of storedModels(input.model)) {
    const candidate = { provider: model.provider, modelId: model.name };
    if (!isModelAllowed(models.allowed, candidate)) {
      throw createModelNotAllowedError(
        `Model "${model.provider}/${model.name}" is not allowed by the Agent Builder model policy`,
        models.allowed ?? [],
        candidate,
      );
    }
    if (features.model === false && models.default && !isModelAllowed([models.default], candidate)) {
      throw createModelNotAllowedError(
        `Model "${model.provider}/${model.name}" does not match the locked Agent Builder default model`,
        [models.default],
        candidate,
      );
    }
  }
}
