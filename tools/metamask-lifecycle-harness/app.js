/**
 * CipherLayer MetaMask Lifecycle Harness — originator-side dapp logic.
 *
 * This is the FIRST real external-signer test (ADR-005 amendment, AC-004,
 * CL-WAL-010). It never touches key material — MetaMask holds the key and
 * is the only component that can authorize a signature, exactly mirroring
 * the CipherLayer Vault's own invariant ("only the Vault can sign") for an
 * external signer.
 *
 * Safety rules enforced in code, not just by convention:
 *  - refuses any injected provider that does not identify as MetaMask
 *    (isMetaMask, cross-checked via EIP-6963 when multiple wallets are
 *    installed) — no silent fallback to some other extension;
 *  - refuses every chain except Sepolia (11155111 / 0xaa36a7) — no mainnet
 *    path exists in this file at all;
 *  - the Send button is inert until the exact approval phrase is typed,
 *    matching the CLI's --yes / approval-phrase discipline elsewhere in
 *    the family (CL-WAL-007);
 *  - this page's approval is necessary but not sufficient — MetaMask's own
 *    popup is the real, non-bypassable confirmation surface.
 */
(function () {
  "use strict";

  const SEPOLIA_CHAIN_ID_HEX = "0xaa36a7"; // 11155111
  const SEPOLIA_PARAMS = {
    chainId: SEPOLIA_CHAIN_ID_HEX,
    chainName: "Sepolia",
    nativeCurrency: { name: "Sepolia ETH", symbol: "ETH", decimals: 18 },
    rpcUrls: ["https://ethereum-sepolia-rpc.publicnode.com"],
    blockExplorerUrls: ["https://sepolia.etherscan.io"],
  };
  const APPROVAL_PHRASE = "SEND-METAMASK-SEPOLIA-LIFECYCLE";

  const logEl = document.getElementById("log");
  function log(msg) {
    const line = `[${new Date().toISOString()}] ${msg}`;
    logEl.textContent += line + "\n";
    logEl.scrollTop = logEl.scrollHeight;
    console.log(line);
  }

  function markDone(stepId) {
    document.getElementById(stepId).classList.add("done");
  }

  // --- state ---
  let provider = null; // the MetaMask EIP-1193 provider, once verified
  let account = null;
  let previewedTx = null;

  // --- EIP-6963 discovery: find the provider that announces as MetaMask
  // even when multiple wallet extensions are installed, instead of trusting
  // whatever happened to grab window.ethereum first. ---
  function discoverMetaMaskProvider() {
    return new Promise((resolve) => {
      const found = [];
      function onAnnounce(event) {
        found.push(event.detail);
      }
      window.addEventListener("eip6963:announceProvider", onAnnounce);
      window.dispatchEvent(new Event("eip6963:requestProvider"));
      setTimeout(() => {
        window.removeEventListener("eip6963:announceProvider", onAnnounce);
        const mm = found.find(
          (p) => p.info && /metamask/i.test(p.info.name || "")
        );
        if (mm) {
          resolve(mm.provider);
          return;
        }
        // Fallback: legacy window.ethereum, but only if it self-identifies.
        if (window.ethereum && window.ethereum.isMetaMask) {
          resolve(window.ethereum);
          return;
        }
        resolve(null);
      }, 250);
    });
  }

  document.getElementById("btn-connect").onclick = async () => {
    log("Discovering injected providers (EIP-6963)...");
    provider = await discoverMetaMaskProvider();
    if (!provider) {
      log(
        "REFUSED: no provider identified as MetaMask. This harness will not fall back to any other wallet."
      );
      return;
    }
    try {
      const accounts = await provider.request({ method: "eth_requestAccounts" });
      account = accounts[0];
      log(`Connected to MetaMask. Account: ${account}`);
      markDone("step-connect");
      document.getElementById("btn-chain").disabled = false;
    } catch (e) {
      log(`Connection refused: ${e.message}`);
    }
  };

  document.getElementById("btn-chain").onclick = async () => {
    const chainId = await provider.request({ method: "eth_chainId" });
    if (chainId === SEPOLIA_CHAIN_ID_HEX) {
      log("Already on Sepolia.");
      markDone("step-chain");
      document.getElementById("btn-preview").disabled = false;
      document.getElementById("recipient").value = account;
      return;
    }
    log(`Current chain ${chainId} is not Sepolia. Requesting switch...`);
    try {
      await provider.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: SEPOLIA_CHAIN_ID_HEX }],
      });
    } catch (switchErr) {
      if (switchErr.code === 4902) {
        log("Sepolia not registered in MetaMask; requesting add...");
        await provider.request({
          method: "wallet_addEthereumChain",
          params: [SEPOLIA_PARAMS],
        });
      } else {
        log(`Switch refused: ${switchErr.message}`);
        return;
      }
    }
    const confirmChain = await provider.request({ method: "eth_chainId" });
    if (confirmChain !== SEPOLIA_CHAIN_ID_HEX) {
      log(`REFUSED: chain is ${confirmChain}, not Sepolia. Will not proceed.`);
      return;
    }
    log("Now on Sepolia.");
    markDone("step-chain");
    document.getElementById("btn-preview").disabled = false;
    document.getElementById("recipient").value = account;
  };

  document.getElementById("btn-preview").onclick = async () => {
    const to = document.getElementById("recipient").value.trim();
    const valueWei = document.getElementById("value-wei").value.trim();
    if (!/^0x[a-fA-F0-9]{40}$/.test(to)) {
      log("REFUSED: recipient is not a well-formed address.");
      return;
    }
    let valueHex;
    try {
      valueHex = "0x" + BigInt(valueWei).toString(16);
    } catch {
      log("REFUSED: value-wei is not a valid integer.");
      return;
    }
    const chainId = await provider.request({ method: "eth_chainId" });
    if (chainId !== SEPOLIA_CHAIN_ID_HEX) {
      log("REFUSED: chain changed since step 2. Re-run step 2.");
      return;
    }
    previewedTx = { from: account, to, value: valueHex };
    log(`Preview: from=${account} to=${to} value=${valueWei} wei (${valueHex}) chain=Sepolia`);
    markDone("step-preview");
    document.getElementById("approval-phrase").disabled = false;
    document.getElementById("approval-phrase").oninput = (e) => {
      document.getElementById("btn-send").disabled = e.target.value !== APPROVAL_PHRASE;
    };
  };

  document.getElementById("btn-send").onclick = async () => {
    const phrase = document.getElementById("approval-phrase").value;
    if (phrase !== APPROVAL_PHRASE) {
      log("REFUSED: approval phrase does not match.");
      return;
    }
    if (!previewedTx) {
      log("REFUSED: no previewed transaction.");
      return;
    }
    log("Approval phrase accepted. Requesting eth_sendTransaction — MetaMask will now show ITS OWN confirmation popup. This harness cannot and will not click through it for you.");
    try {
      const txHash = await provider.request({
        method: "eth_sendTransaction",
        params: [previewedTx],
      });
      log(`MetaMask returned tx hash: ${txHash}`);
      markDone("step-send");
      window.__cipherlayerTxHash = txHash;
      document.getElementById("btn-verify").disabled = false;
    } catch (e) {
      log(`Send refused or rejected in MetaMask: ${e.message}`);
    }
  };

  document.getElementById("btn-verify").onclick = async () => {
    const txHash = window.__cipherlayerTxHash;
    log(`Polling for receipt of ${txHash} (observer role, read-only)...`);
    for (let i = 0; i < 60; i++) {
      const receipt = await provider.request({
        method: "eth_getTransactionReceipt",
        params: [txHash],
      });
      if (receipt) {
        const status = receipt.status === "0x1" ? "success" : "reverted";
        log(`Receipt found: block ${receipt.blockNumber}, status ${status}`);
        markDone("step-verify");
        const artifact = {
          schema: "cipherlayer-metamask-lifecycle.v1",
          network: "sepolia",
          chain_id: 11155111,
          from: previewedTx.from,
          to: previewedTx.to,
          value_wei: BigInt(previewedTx.value).toString(),
          tx_hash: txHash,
          block_number: parseInt(receipt.blockNumber, 16),
          status,
          observed_at: new Date().toISOString(),
        };
        document.getElementById("artifact").value = JSON.stringify(artifact, null, 2);
        document.getElementById("artifact-wrap").style.display = "block";
        return;
      }
      await new Promise((r) => setTimeout(r, 3000));
    }
    log("Timed out waiting for receipt after 60 attempts (~3 min). Check a block explorer manually.");
  };
})();
