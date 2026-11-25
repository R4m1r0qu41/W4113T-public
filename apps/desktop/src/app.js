// Every chain adapter this repo actually ships (README §Repository layout):
// EVM (Anvil dev + Sepolia testnet + L2 registry entries), Solana (ADR-016),
// Bitcoin (ADR-017). `networkClass` matches cipherlayer_types::NetworkClass
// (Development/Testnet/Mainnet) so the same vocabulary the trust core uses
// for signing gates is what the operator sees here (UX-first sequencing,
// roadmap "W2 — Desktop wallet UI": testnet/mainnet as a non-event, not a
// hidden flag).
const CHAINS = [
  { id: "anvil", name: "Anvil (dev)", networkClass: "development" },
  { id: "btc-regtest", name: "Bitcoin Regtest (dev)", networkClass: "development" },
  { id: "sepolia", name: "Ethereum Sepolia", networkClass: "testnet" },
  { id: "sol-devnet", name: "Solana Devnet", networkClass: "testnet" },
  { id: "arbitrum", name: "Arbitrum One", networkClass: "mainnet" },
  { id: "base", name: "Base", networkClass: "mainnet" },
  { id: "op", name: "OP Mainnet", networkClass: "mainnet" },
  { id: "sol-mainnet", name: "Solana Mainnet Beta", networkClass: "mainnet" },
];

const CHAIN_BY_ID = new Map(CHAINS.map((chain) => [chain.id, chain]));

function chainMeta(id) {
  return CHAIN_BY_ID.get(id);
}

const state = {
  activeView: "assets",
  profileFilter: "all",
  assetFilters: {
    network: "all",
    type: "all",
    chains: new Set(),
    search: "",
  },
  // Fixture holdings spread across every chain family above, mixing tokens
  // and NFTs — enough volume that "one screen, every chain, every asset"
  // actually has to prove itself under filtering, instead of looking tidy
  // only because the fixture was thin. Reconciled by hand against
  // cipherlayer-cli/src/console.rs's demo_assets_for on every change — same
  // chains, same per-chain holdings.
  assets: [
    { chain: "anvil", kind: "token", symbol: "ETH", name: "Ether (native)", amount: "10.0 ETH" },
    { chain: "anvil", kind: "token", symbol: "TT", name: "Sample ERC-20 (demo)", amount: "500 TT" },
    { chain: "anvil", kind: "nft", symbol: "SC", name: "Sample Collectible #1", collection: "Demo Collectibles" },

    { chain: "btc-regtest", kind: "token", symbol: "BTC", name: "Bitcoin (regtest, native)", amount: "2.50000000 BTC" },

    { chain: "sepolia", kind: "token", symbol: "ETH", name: "Ether (native)", amount: "0.42 ETH" },
    { chain: "sepolia", kind: "token", symbol: "USDC", name: "USD Coin (test)", amount: "120.00 USDC" },
    { chain: "sepolia", kind: "nft", symbol: "TB", name: "Testnet Badge #7", collection: "Faucet Badges" },

    { chain: "sol-devnet", kind: "token", symbol: "SOL", name: "Solana (native, devnet)", amount: "5.0 SOL" },
    { chain: "sol-devnet", kind: "token", symbol: "USDC", name: "USD Coin (devnet)", amount: "50.00 USDC" },

    { chain: "arbitrum", kind: "token", symbol: "ETH", name: "Ether (native)", amount: "0.081 ETH" },
    { chain: "arbitrum", kind: "token", symbol: "ARB", name: "Arbitrum", amount: "64.2 ARB" },
    { chain: "arbitrum", kind: "nft", symbol: "AO", name: "Arbitrum Odyssey #214", collection: "Arbitrum Odyssey" },
    { chain: "arbitrum", kind: "nft", symbol: "AO", name: "Arbitrum Odyssey #891", collection: "Arbitrum Odyssey" },

    { chain: "base", kind: "token", symbol: "ETH", name: "Ether (native)", amount: "0.015 ETH" },
    { chain: "base", kind: "nft", symbol: "BN", name: "demo.base.eth", collection: "Basenames" },

    { chain: "op", kind: "token", symbol: "ETH", name: "Ether (native)", amount: "0.003 ETH" },
    { chain: "op", kind: "token", symbol: "OP", name: "Optimism", amount: "18.9 OP" },

    { chain: "sol-mainnet", kind: "token", symbol: "SOL", name: "Solana (native)", amount: "1.24 SOL" },
    { chain: "sol-mainnet", kind: "nft", symbol: "ML", name: "Mad Lads #4021", collection: "Mad Lads" },
    { chain: "sol-mainnet", kind: "nft", symbol: "TN", name: "Tensorians #118", collection: "Tensorians" },
  ],
  transaction: {
    intentTitle: "Native transfer",
    confidence: "confidence 0.92",
    from: "0xf39F...2266",
    to: "0x2d24...91B8",
    value: "1 wei",
    network: "Anvil local development (31337)",
    simulationStatus: "Success",
    risk: "Unknown risk",
    protocol: "protocol v0.3",
    policyVerdict: "Escalate",
    decisionNote:
      "Final approval is made only by cipherlayer-vaultd on the Vault-owned confirmation surface.",
    evidence: [
      {
        label: "Simulation",
        value: "State-diff simulation completed on local Anvil.",
        tone: "good",
      },
      {
        label: "Risk",
        value: "UNKNOWN - no detector evidence is treated as low risk.",
        tone: "warn",
      },
      {
        label: "Transport",
        value: "Browser-connect contract is host-attested at protocol v0.3.",
        tone: "neutral",
      },
    ],
    reasons: [
      "POL-RSK-002: unknown risk evidence escalates review",
      "POL-CHN-001: local development chain allowed",
      "POL-SIM-001: simulation evidence present",
    ],
  },
  accounts: [
    {
      name: "Anvil dev account",
      type: "hot",
      address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
      custody: "MOCKED custody",
      status: "development only",
    },
    {
      name: "Sepolia external signer",
      type: "hot",
      address: "operator selected",
      custody: "external authority",
      status: "testnet only",
    },
    {
      name: "Watch profile",
      type: "watch",
      address: "not configured",
      custody: "watch-only",
      status: "no signing",
    },
  ],
  policy: [
    {
      rule: "Unlimited approvals",
      action: "Block by default",
      code: "POL-APR-001",
    },
    {
      rule: "Unknown decoded action",
      action: "Escalate or deny",
      code: "POL-UNK-001",
    },
    {
      rule: "Network class",
      action: "Development signing only",
      code: "POL-CHN-001",
    },
    {
      rule: "AI and risk text",
      action: "Cannot authorize",
      code: "POL-AI-001",
    },
  ],
  audit: [
    {
      state: "REQUEST_RECEIVED",
      detail: "Envelope accepted from CLI prototype fixture",
    },
    {
      state: "INTENT_DECODED",
      detail: "Native transfer decoded deterministically",
    },
    {
      state: "RISK_EVALUATED",
      detail: "Risk remained UNKNOWN and visible",
    },
    {
      state: "POLICY_EVALUATED",
      detail: "Escalation required before Vault review",
    },
  ],
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

// Resolved once: these containers' identity never changes after page load.
const assetsRoot = $('[data-bind-list="assets"]');
const chainChipsRoot = $('[data-bind-list="chain-chips"]');

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function setText(name, value) {
  const node = $(`[data-bind="${name}"]`);
  if (node) node.textContent = value;
}

function renderEvidence() {
  const root = $('[data-bind-list="evidence"]');
  root.replaceChildren(
    ...state.transaction.evidence.map((item) => {
      const row = el("div", `evidence-item ${item.tone}`);
      row.append(el("span", "", item.label), el("strong", "", item.value));
      return row;
    }),
  );
}

function renderReasons() {
  const root = $('[data-bind-list="reasons"]');
  root.replaceChildren(
    ...state.transaction.reasons.map((reason) => {
      const item = document.createElement("li");
      item.textContent = reason;
      return item;
    }),
  );
}

function renderAccounts() {
  const root = $('[data-bind-list="accounts"]');
  const rows = state.accounts
    .filter((account) => state.profileFilter === "all" || account.type === state.profileFilter)
    .map((account) => {
      const row = el("article", "account-row");
      const identity = el("div");
      identity.append(el("strong", "", account.name), el("span", "", account.address));
      row.append(
        identity,
        el("span", "", account.custody),
        el("span", "", account.status),
      );
      return row;
    });
  root.replaceChildren(...rows);
}

function renderPolicy() {
  const root = $('[data-bind-list="policy"]');
  root.replaceChildren(
    ...state.policy.map((policy) => {
      const item = el("article", "policy-item");
      item.append(el("span", "", policy.code), el("strong", "", policy.rule), el("p", "", policy.action));
      return item;
    }),
  );
}

const NETWORK_META = {
  development: { tone: "neutral", label: "Development" },
  testnet: { tone: "good", label: "Testnet" },
  mainnet: { tone: "warn", label: "Mainnet" },
};

function networkMeta(networkClass) {
  return NETWORK_META[networkClass] ?? { tone: "neutral", label: networkClass };
}

function filteredAssets() {
  const filters = state.assetFilters;
  const query = filters.search.trim().toLowerCase();
  return state.assets.filter((asset) => {
    const meta = chainMeta(asset.chain);
    if (filters.network !== "all" && meta.networkClass !== filters.network) return false;
    if (filters.type !== "all" && asset.kind !== filters.type) return false;
    if (filters.chains.size > 0 && !filters.chains.has(asset.chain)) return false;
    if (query) {
      const haystack = `${asset.name} ${asset.symbol} ${asset.collection ?? ""}`.toLowerCase();
      if (!haystack.includes(query)) return false;
    }
    return true;
  });
}

function groupAssetsByChain(list) {
  const byChain = new Map();
  for (const asset of list) {
    if (!byChain.has(asset.chain)) byChain.set(asset.chain, []);
    byChain.get(asset.chain).push(asset);
  }
  return CHAINS.filter((chain) => byChain.has(chain.id)).map((chain) => ({
    chain,
    assets: byChain.get(chain.id),
  }));
}

// A small deterministic hue from the symbol string, so token/NFT tiles get
// distinct-looking placeholder art instead of every row looking identical —
// there are no real logos/images in this fixture-driven prototype.
function symbolHue(symbol) {
  let hash = 0;
  for (const char of symbol) hash = (hash * 31 + char.charCodeAt(0)) % 360;
  return hash;
}

function renderAssetIcon(symbol, extraClass) {
  const icon = el("span", `asset-icon${extraClass ? ` ${extraClass}` : ""}`, symbol.slice(0, 2).toUpperCase());
  const hue = symbolHue(symbol);
  icon.style.background = `hsl(${hue} 70% 92%)`;
  icon.style.color = `hsl(${hue} 55% 32%)`;
  return icon;
}

function renderTokenRow(asset) {
  const row = el("div", "token-row");
  const identity = el("div");
  identity.append(el("strong", "", asset.name), el("span", "", asset.symbol));
  row.append(renderAssetIcon(asset.symbol), identity, el("strong", "amount", asset.amount));
  return row;
}

function renderNftTile(asset) {
  const tile = el("div", "nft-tile");
  const caption = el("div");
  caption.append(el("strong", "", asset.name), el("span", "", asset.collection));
  tile.append(renderAssetIcon(asset.symbol, "nft-art"), caption);
  return tile;
}

function renderChainGroups(list) {
  const groups = groupAssetsByChain(list);

  if (groups.length === 0) {
    assetsRoot.replaceChildren(
      el(
        "p",
        "empty-state",
        "No assets match these filters. Widen the network, chain, or type filter to see more.",
      ),
    );
    return;
  }

  assetsRoot.replaceChildren(
    ...groups.map(({ chain, assets }) => {
      const tokens = assets.filter((asset) => asset.kind === "token");
      const nfts = assets.filter((asset) => asset.kind === "nft");

      const group = el("article", "chain-group");
      const head = el("div", "chain-group-head");
      const heading = el("div");
      heading.append(
        el("strong", "", chain.name),
        el("span", "", `${assets.length} ${assets.length === 1 ? "asset" : "assets"}`),
      );
      const { tone, label } = networkMeta(chain.networkClass);
      head.append(heading, el("span", `status-pill ${tone}`, label));
      group.append(head);

      if (tokens.length) {
        const tokenList = el("div", "token-list");
        tokenList.replaceChildren(...tokens.map(renderTokenRow));
        group.append(tokenList);
      }
      if (nfts.length) {
        const nftGrid = el("div", "nft-grid");
        nftGrid.replaceChildren(...nfts.map(renderNftTile));
        group.append(nftGrid);
      }
      return group;
    }),
  );
}

function renderChainChips() {
  chainChipsRoot.replaceChildren(
    ...CHAINS.map((chain) => {
      const chip = el("button", "chip", chain.name);
      chip.type = "button";
      chip.dataset.chainChip = chain.id;
      chip.classList.toggle("is-selected", state.assetFilters.chains.has(chain.id));
      return chip;
    }),
  );
}

function renderAssetsSummary(list) {
  const chains = new Set(list.map((asset) => asset.chain)).size;
  const tokens = list.filter((asset) => asset.kind === "token").length;
  const nfts = list.filter((asset) => asset.kind === "nft").length;
  setText(
    "assetsSummary",
    `${chains} ${chains === 1 ? "chain" : "chains"} held · ${tokens} tokens · ${nfts} NFTs`,
  );
}

function renderAssets() {
  const list = filteredAssets();
  renderChainChips();
  renderAssetsSummary(list);
  renderChainGroups(list);
}

function renderAudit() {
  const root = $('[data-bind-list="audit"]');
  root.replaceChildren(
    ...state.audit.map((event) => {
      const item = el("li");
      item.append(el("strong", "", event.state), el("span", "", event.detail));
      return item;
    }),
  );
}

// Per-view topbar content. Every view carries its own panel-level heading
// (see each <section data-view-panel> in index.html), so by default the
// topbar collapses to plain wallet branding; a view opts into its own
// eyebrow/title — and, via showStatusStrip, the per-transaction chain/risk/
// protocol pills — by adding an entry here, not by editing updateTopbar.
// Today only Review needs either.
const TOPBAR_BY_VIEW = {
  review: { eyebrow: "Local prototype", title: "Transaction review", showStatusStrip: true },
};
const DEFAULT_TOPBAR = { eyebrow: "CipherLayer", title: "Wallet", showStatusStrip: false };

function updateTopbar(view) {
  const { eyebrow, title, showStatusStrip } = TOPBAR_BY_VIEW[view] ?? DEFAULT_TOPBAR;
  setText("topbarEyebrow", eyebrow);
  setText("topbarTitle", title);
  $(".status-strip").classList.toggle("is-hidden", !showStatusStrip);
}

function switchView(view) {
  state.activeView = view;
  document.body.querySelector("#app").dataset.view = view;
  $$(".nav-item").forEach((item) => {
    item.classList.toggle("is-active", item.dataset.target === view);
  });
  $$("[data-view-panel]").forEach((panel) => {
    panel.classList.toggle("is-visible", panel.dataset.viewPanel === view);
  });
  updateTopbar(view);
}

// A single-select segmented control: clicking a button sets one
// state.assetFilters field to that button's dataset value and highlights it
// among its siblings. Both the network and asset-type filter bars share this
// shape.
function bindSegmentedFilter(selector, datasetKey, filterKey) {
  $$(selector).forEach((button) => {
    button.addEventListener("click", () => {
      state.assetFilters[filterKey] = button.dataset[datasetKey];
      $$(selector).forEach((item) => item.classList.toggle("is-selected", item === button));
      renderAssets();
    });
  });
}

function bindEvents() {
  $$(".nav-item").forEach((button) => {
    button.addEventListener("click", () => switchView(button.dataset.target));
  });

  bindSegmentedFilter("[data-network-filter]", "networkFilter", "network");
  bindSegmentedFilter("[data-type-filter]", "typeFilter", "type");

  // Chips are re-rendered on every filter change, so their click handling is
  // delegated to the stable container rather than bound per-chip.
  chainChipsRoot.addEventListener("click", (event) => {
    const chip = event.target.closest("[data-chain-chip]");
    if (!chip) return;
    const id = chip.dataset.chainChip;
    if (state.assetFilters.chains.has(id)) {
      state.assetFilters.chains.delete(id);
    } else {
      state.assetFilters.chains.add(id);
    }
    renderAssets();
  });

  $('[data-action="asset-search"]').addEventListener("input", (event) => {
    state.assetFilters.search = event.target.value;
    renderAssets();
  });

  $$("[data-profile-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      state.profileFilter = button.dataset.profileFilter;
      $$("[data-profile-filter]").forEach((item) => {
        item.classList.toggle("is-selected", item === button);
      });
      renderAccounts();
    });
  });

  $('[data-action="reject"]').addEventListener("click", () => {
    state.transaction.decisionNote =
      "Rejected in the desktop prototype. No signing request was sent to the Vault.";
    setText("decisionNote", state.transaction.decisionNote);
  });

  $('[data-action="vault-review"]').addEventListener("click", () => {
    state.transaction.decisionNote =
      "Ready for cipherlayer-vaultd confirm_and_sign. This prototype does not approve locally.";
    setText("decisionNote", state.transaction.decisionNote);
  });
}

function render() {
  updateTopbar(state.activeView);
  setText("chain", "Anvil 31337");
  setText("risk", state.transaction.risk);
  setText("protocol", state.transaction.protocol);
  setText("intentTitle", state.transaction.intentTitle);
  setText("confidence", state.transaction.confidence);
  setText("from", state.transaction.from);
  setText("to", state.transaction.to);
  setText("value", state.transaction.value);
  setText("network", state.transaction.network);
  setText("simulationStatus", state.transaction.simulationStatus);
  setText("policyVerdict", state.transaction.policyVerdict);
  setText("decisionNote", state.transaction.decisionNote);
  renderEvidence();
  renderReasons();
  renderAssets();
  renderAccounts();
  renderPolicy();
  renderAudit();
}

bindEvents();
render();
