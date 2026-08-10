import type {
  BuilderAgentConfiguration,
  BuilderModelPolicy,
  BuilderProviderModelEntry,
  IAgentBuilder,
  IMastraEditor,
} from '@mastra/core/editor';

const TRUSTED_PROVIDER_ALIASES: Readonly<Record<string, string>> = {
  'openai.chat': 'openai',
};

function normalizeProvider(provider: string): string {
  return TRUSTED_PROVIDER_ALIASES[provider] ?? provider;
}

/** Match a runtime model against a Builder provider/model allowlist. */
export function isBuilderModelAllowed(
  allowed: BuilderProviderModelEntry[] | undefined,
  model: { provider: string; modelId?: string },
): boolean {
  if (allowed === undefined) return true;
  return allowed.some(entry => {
    if (normalizeProvider(model.provider) !== normalizeProvider(entry.provider)) return false;
    return entry.modelId === undefined || entry.modelId === model.modelId;
  });
}

/** Convert the configured Builder model slice into the server response contract. */
export function toBuilderModelPolicy(builder: IAgentBuilder | undefined): BuilderModelPolicy {
  if (!builder?.enabled) return { active: false };
  const models = builder.getConfiguration().agent?.models;

  return {
    active: true,
    pickerVisible: builder.getFeatures().agent.model !== false,
    ...(models?.allowed !== undefined ? { allowed: models.allowed } : {}),
    ...(models?.default !== undefined ? { default: models.default } : {}),
  };
}

export interface BuilderPickerVisibility {
  visibleTools: string[] | null;
  visibleAgents: string[] | null;
  visibleWorkflows: string[] | null;
  warnings: string[];
}

export interface ResolveBuilderPickerVisibilityOptions {
  config?: Pick<BuilderAgentConfiguration, 'tools' | 'agents' | 'workflows'>;
  registeredToolIds?: string[];
  registeredAgentIds?: string[];
  registeredWorkflowIds?: string[];
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

/** Resolve route-specific picker IDs and warnings against the current registries. */
export function resolveBuilderPickerVisibility(
  options: ResolveBuilderPickerVisibilityOptions,
): BuilderPickerVisibility {
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

/** Resolve an optional editor's active Builder model policy for server routes. */
export async function resolveBuilderModelPolicy(editor: IMastraEditor | undefined): Promise<BuilderModelPolicy> {
  if (!editor) return { active: false };
  if (typeof editor.resolveBuilder !== 'function') return { active: false };
  if (typeof editor.hasEnabledBuilderConfig === 'function' && !editor.hasEnabledBuilderConfig()) {
    return { active: false };
  }

  // Degrade to inactive on builder-resolution failure rather than letting the
  // rejection escape: agent execution routes seed this on every request, so a
  // transient failure must not 500 the entire route.
  try {
    return toBuilderModelPolicy(await editor.resolveBuilder());
  } catch {
    return { active: false };
  }
}
