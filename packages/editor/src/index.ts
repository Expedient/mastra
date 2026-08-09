import { Mastra } from '@mastra/core';
import type {
  IMastraEditor,
  MastraEditorConfig,
  FilesystemProvider,
  SandboxProvider,
  BlobStoreProvider,
  BrowserProvider,
  WorkspaceProvider,
} from '@mastra/core/editor';
import type { IMastraLogger as Logger } from '@mastra/core/logger';
import { BUILT_IN_PROCESSOR_PROVIDERS } from '@mastra/core/processor-provider';
import type { ProcessorProvider } from '@mastra/core/processor-provider';
import {
  createGitHubSourceControlProviderFromEnv,
  FilesystemStore,
  MastraCompositeStore,
  SourceAgentsSourceControl,
} from '@mastra/core/storage';
import type { BlobStore, SourceControlProvider } from '@mastra/core/storage';
import { UnknownToolProviderError } from '@mastra/core/tool-provider';
import type { ToolProvider } from '@mastra/core/tool-provider';

import {
  EditorAgentNamespace,
  EditorMCPNamespace,
  EditorMCPServerNamespace,
  EditorPromptNamespace,
  EditorScorerNamespace,
  EditorWorkspaceNamespace,
  EditorSkillNamespace,
  EditorFavoritesNamespace,
} from './namespaces';
import { localFilesystemProvider, localSandboxProvider } from './providers';

export type { MastraEditorConfig };

export { renderTemplate } from './template-engine';
export { evaluateRuleGroup } from './rule-evaluator';
export { resolveInstructionBlocks } from './instruction-builder';
export {
  EditorNamespace,
  CrudEditorNamespace,
  EditorAgentNamespace,
  EditorMCPNamespace,
  EditorMCPServerNamespace,
  EditorPromptNamespace,
  EditorScorerNamespace,
  EditorWorkspaceNamespace,
  EditorSkillNamespace,
  EditorFavoritesNamespace,
} from './namespaces';
export type { StorageAdapter } from './namespaces';
export { localFilesystemProvider, localSandboxProvider } from './providers';
export type { BrowserProvider } from '@mastra/core/editor';

export class MastraEditor implements IMastraEditor {
  /** @internal — exposed for namespace classes, not part of public API */
  __mastra?: Mastra;
  /** @internal — exposed for namespace classes, not part of public API */
  __logger?: Logger;

  private __toolProviders: Record<string, ToolProvider>;
  private __processorProviders: Record<string, ProcessorProvider>;
  private __source?: 'code' | 'db';
  private __codePath: string;
  private __sourceControlProvider?: SourceControlProvider;

  /**
   * @internal — exposed for namespace classes to hydrate stored workspace configs.
   * Maps provider ID (e.g., 'local', 's3') to the provider descriptor.
   * Built-in providers are auto-registered; additional providers come from config.
   */
  readonly __filesystems: Map<string, FilesystemProvider>;

  /**
   * @internal — exposed for namespace classes to hydrate stored workspace configs.
   * Maps provider ID (e.g., 'local', 'e2b') to the provider descriptor.
   * Built-in providers are auto-registered; additional providers come from config.
   */
  readonly __sandboxes: Map<string, SandboxProvider>;

  /**
   * @internal — exposed for namespace classes to resolve blob stores.
   * Maps provider ID (e.g., 'storage', 's3') to the provider descriptor.
   * The built-in 'storage' provider uses the configured storage backend.
   * Additional providers come from config.
   */
  readonly __blobStores: Map<string, BlobStoreProvider>;

  /**
   * @internal — exposed for namespace classes to hydrate stored browser configs.
   * Maps provider ID (e.g., 'stagehand', 'agent-browser') to the provider descriptor.
   * No built-in providers — browser packages must be registered via config.
   */
  readonly __browsers: Map<string, BrowserProvider>;

  /**
   * @internal — exposed for namespace classes to hydrate stored workspace configs.
   * Maps provider ID to the provider descriptor.
   * No built-in providers — workspace providers must be registered via config.
   */
  readonly __workspaces: Map<string, WorkspaceProvider>;

  public readonly agent: EditorAgentNamespace;
  public readonly mcp: EditorMCPNamespace;
  public readonly mcpServer: EditorMCPServerNamespace;
  public readonly prompt: EditorPromptNamespace;
  public readonly scorer: EditorScorerNamespace;
  public readonly workspace: EditorWorkspaceNamespace;
  public readonly skill: EditorSkillNamespace;
  public readonly favorites: EditorFavoritesNamespace;

  constructor(config?: MastraEditorConfig) {
    this.__logger = config?.logger;
    this.__toolProviders = config?.toolProviders ?? {};
    this.__processorProviders = { ...BUILT_IN_PROCESSOR_PROVIDERS, ...config?.processorProviders };
    this.__source = config?.source;
    this.__codePath = config?.codePath ?? './mastra/editor';
    this.__sourceControlProvider =
      config?.sourceControlProvider ??
      createGitHubSourceControlProviderFromEnv(process.env, { pathPrefix: this.__codePath });

    // Built-in providers are always registered first, then merged with user-provided ones
    this.__filesystems = new Map<string, FilesystemProvider>();
    this.__filesystems.set(localFilesystemProvider.id, localFilesystemProvider);
    for (const [id, provider] of Object.entries(config?.filesystems ?? {})) {
      this.__filesystems.set(id, provider);
    }

    this.__sandboxes = new Map<string, SandboxProvider>();
    this.__sandboxes.set(localSandboxProvider.id, localSandboxProvider);
    for (const [id, provider] of Object.entries(config?.sandboxes ?? {})) {
      this.__sandboxes.set(id, provider);
    }

    // Blob store providers — no built-in default since the 'storage' fallback
    // is handled at resolve time via storage.getStore('blobs')
    this.__blobStores = new Map<string, BlobStoreProvider>();
    for (const [id, provider] of Object.entries(config?.blobStores ?? {})) {
      this.__blobStores.set(id, provider);
    }

    // Browser providers — no built-in providers; browser packages must be registered
    this.__browsers = new Map<string, BrowserProvider>();
    for (const [id, provider] of Object.entries(config?.browsers ?? {})) {
      this.__browsers.set(id, provider);
    }

    // Workspace providers — no built-in providers; workspace packages must be registered
    this.__workspaces = new Map<string, WorkspaceProvider>();
    for (const [id, provider] of Object.entries(config?.workspaces ?? {})) {
      this.__workspaces.set(id, provider);
    }

    this.agent = new EditorAgentNamespace(this);
    this.mcp = new EditorMCPNamespace(this);
    this.mcpServer = new EditorMCPServerNamespace(this);
    this.prompt = new EditorPromptNamespace(this);
    this.scorer = new EditorScorerNamespace(this);
    this.workspace = new EditorWorkspaceNamespace(this);
    this.skill = new EditorSkillNamespace(this);
    this.favorites = new EditorFavoritesNamespace(this);
  }

  /**
   * Register this editor with a Mastra instance.
   * This gives the editor access to Mastra's storage, tools, workflows, etc.
   */
  registerWithMastra(mastra: Mastra): void {
    this.__mastra = mastra;
    if (!this.__logger) {
      this.__logger = mastra.getLogger();
    }

    // Code source routes editor-owned domains away from the app's primary storage.
    // Local development uses a FilesystemStore at `codePath`; hosted/self-hosted
    // environments can provide a source provider so agent overrides are persisted
    // through source-control operations instead of a local container filesystem.
    if (this.__source === 'code') {
      const existingStorage = mastra.getStorage();

      if (this.__sourceControlProvider) {
        const sourceAgentsStore = new SourceAgentsSourceControl({
          provider: this.__sourceControlProvider,
        });
        const filesystemStore = new FilesystemStore({ dir: this.__codePath });

        mastra.setStorage(
          new MastraCompositeStore({
            id: `${existingStorage?.id ?? 'mastra'}-with-editor-source-control`,
            ...(existingStorage ? { default: existingStorage } : {}),
            editor: filesystemStore,
            domains: { agents: sourceAgentsStore },
          }),
        );
      } else {
        const filesystemStore = new FilesystemStore({ dir: this.__codePath });

        if (existingStorage) {
          mastra.setStorage(
            new MastraCompositeStore({
              id: `${existingStorage.id}-with-editor-filesystem`,
              default: existingStorage,
              editor: filesystemStore,
            }),
          );
        } else {
          mastra.setStorage(filesystemStore);
        }
      }
    }
  }

  /** Returns the editor's configured source, or undefined if unset. */
  getSource(): 'code' | 'db' | undefined {
    return this.__source;
  }

  /** Returns the configured source control provider, if any. */
  getSourceControlProvider(): SourceControlProvider | undefined {
    return this.__sourceControlProvider;
  }

  /** Registered tool providers */
  getToolProvider(id: string): ToolProvider | undefined {
    return this.__toolProviders[id];
  }

  /**
   * Like {@link getToolProvider}, but throws {@link UnknownToolProviderError}
   * when the id is unknown.
   */
  getToolProviderOrThrow(id: string): ToolProvider {
    const provider = this.__toolProviders[id];
    if (!provider) {
      throw new UnknownToolProviderError(id, Object.keys(this.__toolProviders));
    }
    return provider;
  }

  /** List all registered tool providers */
  getToolProviders(): Record<string, ToolProvider> {
    return this.__toolProviders;
  }

  /** Get a processor provider by ID */
  getProcessorProvider(id: string): ProcessorProvider | undefined {
    return this.__processorProviders[id];
  }

  /** List all registered processor providers */
  getProcessorProviders(): Record<string, ProcessorProvider> {
    return this.__processorProviders;
  }
  /** List all registered filesystem providers */
  getFilesystemProviders(): FilesystemProvider[] {
    return Array.from(this.__filesystems.values());
  }

  /** List all registered sandbox providers */
  getSandboxProviders(): SandboxProvider[] {
    return Array.from(this.__sandboxes.values());
  }

  /** List all registered blob store providers */
  getBlobStoreProviders(): BlobStoreProvider[] {
    return Array.from(this.__blobStores.values());
  }

  /**
   * Resolve a blob store from the provider registry, or fall back to the
   * storage backend's blobs domain.
   *
   * @param providerId - If specified, look up a registered provider by ID
   *   and create a blob store from the given config. If omitted, falls back
   *   to `storage.getStore('blobs')`.
   * @param providerConfig - Provider-specific configuration (only used when
   *   `providerId` is specified).
   */
  async resolveBlobStore(providerId?: string, providerConfig?: Record<string, unknown>): Promise<BlobStore> {
    // If a specific provider is requested, resolve it
    if (providerId) {
      const provider = this.__blobStores.get(providerId);
      if (!provider) {
        throw new Error(
          `Blob store provider "${providerId}" is not registered. ` +
            `Register it via new MastraEditor({ blobStores: { '${providerId}': yourProvider } })`,
        );
      }
      const blobStore = await provider.createBlobStore(providerConfig ?? {});
      await blobStore.init();
      return blobStore;
    }

    // Fall back to storage backend's blobs domain
    const storage = this.__mastra?.getStorage();
    if (!storage) throw new Error('Storage is not configured');
    const blobStore = await storage.getStore('blobs');
    if (!blobStore) throw new Error('Blob storage domain is not available');
    return blobStore;
  }
}
