// ============================================================
// attack_ui.js — Attack Tab UI Controller
// Manages all attack-specific UI panels, terminal logging,
// and orchestrates the 8-step attack visualization
// ============================================================

const AttackUI = (() => {
    let sim = null;
    let logCallback = null;
    let stateCallback = null;
    let faultVFXCallback = null;
    let keySpaceAnimCallback = null;

    // Current animation state
    let atkAnimState = {
        phase: 0, // sub-phase within a step
        timer: null,
        encHistory: [],
        faultHistory: [],
        currentRound: 0,
        totalFaultsInjected: 0,
        icStep: 0, // information combining sub-step
        currentPhase: 0
    };

    const PHASE_LABELS = [
        'Setup', 'Encrypt', 'Fault', 'DFA',
        'Equiv', 'Normalize', 'Combine', 'Recover'
    ];

    function init(callbacks) {
        sim = new AttackEngine.AttackSimulation();
        logCallback = callbacks.log || (() => {});
        stateCallback = callbacks.updateState || (() => {});
        faultVFXCallback = callbacks.faultVFX || (() => {});
        keySpaceAnimCallback = callbacks.keySpaceAnim || (() => {});
        buildPhaseTracker();
    }

    function reset() {
        if (sim) sim.reset();
        atkAnimState = { phase: 0, timer: null, encHistory: [], faultHistory: [], currentRound: 0, totalFaultsInjected: 0, icStep: 0, currentPhase: 0 };
        updateKeySpaceGauge(128);
        updateNibbleGrid(null);
        updateEquationPanel(0, 0);
        updatePhaseTracker(0);
        // Reset diff display
        const diffEl = document.getElementById('atk-diff-display');
        if (diffEl) { diffEl.innerHTML = ''; diffEl.style.display = 'none'; }
        const lsEl = document.getElementById('atk-ls-display');
        if (lsEl) { lsEl.innerHTML = ''; lsEl.style.display = 'none'; }
        const ddtEl = document.getElementById('atk-ddt-display');
        if (ddtEl) ddtEl.innerHTML = '';
    }

    // ---- Phase Tracker ----
    function buildPhaseTracker() {
        const tracker = document.getElementById('atk-phase-tracker');
        if (!tracker) return;
        tracker.innerHTML = '';
        for (let i = 0; i < 8; i++) {
            const step = document.createElement('div');
            step.className = 'phase-step';
            step.title = PHASE_LABELS[i];
            tracker.appendChild(step);
        }
    }

    function updatePhaseTracker(activeStep) {
        atkAnimState.currentPhase = activeStep;
        const steps = document.querySelectorAll('#atk-phase-tracker .phase-step');
        steps.forEach((s, i) => {
            s.className = 'phase-step';
            if (i < activeStep) s.classList.add('done');
            else if (i === activeStep) s.classList.add('active');
        });
        const label = document.getElementById('atk-phase-label');
        const badge = document.getElementById('atk-phase-badge');
        if (label) {
            label.textContent = `Step ${activeStep + 1}/8 — ${PHASE_LABELS[activeStep]}`;
            label.className = 'phase-label active-label';
        }
        if (badge) {
            if (activeStep >= 7) {
                badge.textContent = 'RECOVERED';
                badge.className = 'badge safe';
            } else if (activeStep >= 3) {
                badge.textContent = 'ANALYZING';
                badge.className = 'badge';
            } else {
                badge.textContent = 'ACTIVE';
                badge.className = 'badge';
            }
        }
    }

    // ---- Key Space Gauge ----
    function updateKeySpaceGauge(bits) {
        const label = document.getElementById('atk-keyspace-label');
        const fill = document.getElementById('atk-keyspace-fill');
        const bitsEl = document.getElementById('atk-keyspace-bits');
        const pctEl = document.getElementById('atk-keyspace-pct');
        if (!fill) return;

        const pct = Math.max(0, Math.min(100, (bits / 128) * 100));
        fill.style.width = pct + '%';

        if (pctEl) pctEl.textContent = Math.round(pct) + '%';
        if (bitsEl) bitsEl.textContent = bits + ' bits';

        // Color gradient based on reduction
        if (bits <= 0) {
            fill.style.background = 'linear-gradient(90deg, #00ff66, #00ff66)';
            if (label) { label.textContent = '1 (RECOVERED)'; label.style.color = '#00ff66'; }
            if (bitsEl) { bitsEl.textContent = '0 bits'; bitsEl.style.color = '#00ff66'; }
            if (pctEl) { pctEl.textContent = '0%'; pctEl.style.color = '#00ff66'; }
        } else if (bits <= 32) {
            fill.style.background = 'linear-gradient(90deg, #00ff66, #ffcc00)';
            if (label) { label.textContent = AttackEngine.formatKeySpace(bits); label.style.color = '#ffcc00'; }
            if (bitsEl) bitsEl.style.color = '#ffcc00';
        } else if (bits <= 64) {
            fill.style.background = 'linear-gradient(90deg, #ffcc00, #ff6600)';
            if (label) { label.textContent = AttackEngine.formatKeySpace(bits); label.style.color = '#ff6600'; }
            if (bitsEl) bitsEl.style.color = '#ff6600';
        } else {
            fill.style.background = 'linear-gradient(90deg, #ff3366, #ff0000)';
            if (label) { label.textContent = AttackEngine.formatKeySpace(bits); label.style.color = '#ff3366'; }
            if (bitsEl) bitsEl.style.color = '#ff3366';
        }
        keySpaceAnimCallback(bits);
    }

    // ---- Nibble Candidate Grid ----
    function updateNibbleGrid(candidates) {
        const grid = document.getElementById('atk-nibble-grid');
        const solvedCountEl = document.getElementById('atk-solved-count');
        if (!grid) return;
        grid.innerHTML = '';
        let solvedCount = 0;
        for (let i = 0; i < 32; i++) {
            const cell = document.createElement('div');
            cell.className = 'nibble-cell';
            const count = candidates ? candidates[i].length : 16;
            const val = candidates && count === 1 ? candidates[i][0].toString(16).toUpperCase() : '';
            cell.textContent = count === 1 ? val : count;
            if (count === 1) {
                cell.classList.add('solved');
                solvedCount++;
            } else if (count <= 4) {
                cell.classList.add('narrowed');
            } else {
                cell.classList.add('unknown');
            }
            cell.title = `Nibble ${31-i}: ${count} candidate${count !== 1 ? 's' : ''}${count === 1 ? ' = 0x' + val : ''}`;
            grid.appendChild(cell);
        }
        if (solvedCountEl) solvedCountEl.textContent = solvedCount;
    }

    // ---- Equation System Panel ----
    function updateEquationPanel(rank, total) {
        const rankEl = document.getElementById('atk-eq-rank');
        const totalEl = document.getElementById('atk-eq-total');
        const barEl = document.getElementById('atk-eq-bar');
        const statusEl = document.getElementById('atk-eq-status');
        const pctEl = document.getElementById('atk-eq-pct');
        if (!rankEl) return;
        const target = 768; // full rank
        rankEl.textContent = rank;
        totalEl.textContent = total;
        const pct = Math.min(100, Math.round((rank / target) * 100));
        if (barEl) barEl.style.width = pct + '%';
        if (pctEl) pctEl.textContent = pct + '%';
        // Status pill
        if (statusEl) {
            if (rank >= target) {
                statusEl.textContent = 'Full Rank';
                statusEl.className = 'eq-status-pill solved';
            } else if (rank > 0) {
                statusEl.textContent = 'Building';
                statusEl.className = 'eq-status-pill solving';
            } else {
                statusEl.textContent = 'Waiting';
                statusEl.className = 'eq-status-pill building';
            }
        }
    }

    // ---- Differential Display ----
    function showDifferential(correctHex, faultyHex, diffArr) {
        const el = document.getElementById('atk-diff-display');
        if (!el) return;

        function renderHexRow(labelText, hexStr, diffArr, mode) {
            let html = `<div class="diff-row"><span class="diff-label">${labelText}</span><span class="diff-hex">`;
            for (let i = 0; i < 32; i++) {
                if (i > 0 && i % 8 === 0) html += '<span class="nibble-sep"></span>';
                const d = diffArr[i];
                let cls = '';
                if (mode === 'delta') {
                    cls = d !== 0 ? 'diff-nonzero' : 'diff-zero';
                } else {
                    cls = d !== 0 ? 'diff-active' : '';
                }
                const char = mode === 'delta' ? d.toString(16) : hexStr[i];
                html += `<span class="${cls}">${char}</span>`;
            }
            html += '</span></div>';
            return html;
        }

        let html = renderHexRow('C  =', correctHex, diffArr, 'ct');
        html += renderHexRow("C' =", faultyHex, diffArr, 'ct');
        html += renderHexRow('ΔC =', '', diffArr, 'delta');

        // Summary row
        const activeCount = diffArr.filter(d => d !== 0).length;
        html += `<div class="diff-summary">
            <span>Active nibbles: <span class="active-count">${activeCount}/32</span></span>
            <span>Fault diffusion: ${Math.round(activeCount / 32 * 100)}%</span>
        </div>`;

        el.innerHTML = html;
        el.style.display = 'block';
    }

    // ---- DDT Visualization ----
    function showDDTEntry(deltaIn, deltaOut) {
        const el = document.getElementById('atk-ddt-display');
        if (!el) return;
        const val = AttackEngine.DDT_LS[deltaIn] ? AttackEngine.DDT_LS[deltaIn][deltaOut] : 0;
        el.innerHTML = `<div class="ddt-entry">DDT[${deltaIn.toString(16)}][${deltaOut.toString(16)}] = <span class="ddt-val ${val > 0 ? 'ddt-hit' : 'ddt-miss'}">${val}</span></div>`;
    }

    // ---- Linear Structures Display ----
    function showLinearStructures() {
        const el = document.getElementById('atk-ls-display');
        if (!el) return;
        let html = '<table class="ls-table"><tr><th>α</th><th>→</th><th>β</th><th>Effect</th></tr>';
        AttackEngine.LINEAR_STRUCTURES.forEach(ls => {
            html += `<tr><td>0x${ls.alpha.toString(16)}</td><td>→</td><td>0x${ls.beta.toString(16)}</td>`;
            html += `<td>S(u⊕${ls.alpha.toString(16)}) = S(u)⊕${ls.beta.toString(16)}</td></tr>`;
        });
        html += '</table>';
        html += '<div class="ls-note">4 structures per nibble → 4³² = 2⁶⁴ equivalent keys per round</div>';
        el.innerHTML = html;
        el.style.display = 'block';
    }

    // ============================================================
    // STEP EXECUTORS — Called when entering each attack step
    // ============================================================

    function executeStep1_Setup(ptHex) {
        sim.reset();
        const key = sim.generateSecretKey();
        sim.plaintext = ptHex;

        logCallback(`<br><div class="log-round" style="color:#ffcc00">> IC-DFA ATTACK INITIALIZED</div>`);
        logCallback(`<div class="log-phase">Target: DEFAULT Cipher (80 rounds, Sandwich Architecture)</div>`);
        logCallback(`<div class="log-data">Plaintext: ${ptHex}</div>`);
        logCallback(`<div class="log-data">Secret Key: <span style="color:#ff3366">[HIDDEN — 128-bit target]</span></div>`);
        logCallback(`<div class="log-data">Key Space: 2¹²⁸ = 3.4 × 10³⁸ candidates</div>`);
        logCallback(`<div class="log-highlight">+ Threat model: Attacker can inject bit-flip faults during encryption</div>`);
        logCallback(`<div class="log-highlight">+ Goal: Recover the full 128-bit master key</div>`);

        updateKeySpaceGauge(128);
        updateNibbleGrid(null);
        updateEquationPanel(0, 0);
        updatePhaseTracker(0);

        return { key, plaintext: ptHex };
    }

    function executeStep2_Encrypt(ptHex, roundCallback) {
        const result = sim.encrypt(ptHex);
        atkAnimState.encHistory = result.history;
        updatePhaseTracker(1);

        logCallback(`<br><div class="log-round ls">> CORRECT ENCRYPTION EXECUTING</div>`);
        logCallback(`<div class="log-phase">Running 80 rounds with secret key...</div>`);

        let roundIdx = 0;
        const interval = setInterval(() => {
            if (roundIdx >= 80) {
                clearInterval(interval);
                logCallback(`<br><div class="log-highlight">+ Correct ciphertext C obtained</div>`);
                logCallback(`<div class="log-data">C = ${result.ciphertext}</div>`);
                stateCallback(result.ciphertext, 80);
                return;
            }
            const layerTxt = (roundIdx < 28 || roundIdx >= 52) ? 'LAYER' : 'CORE';
            if (roundIdx % 10 === 0) {
                logCallback(`<div class="log-data">R${roundIdx}-${Math.min(roundIdx+9,79)} [${layerTxt}] → ${result.history[roundIdx+1]}</div>`);
            }
            if (roundCallback) roundCallback(roundIdx, result.history[roundIdx + 1]);
            roundIdx++;
        }, 30);

        atkAnimState.timer = interval;
        return result;
    }

    function executeStep3_FaultInjection(ptHex) {
        updatePhaseTracker(2);
        const faultRound = 76;
        const faultNibble = 0;
        const faultValue = 1;

        logCallback(`<br><div class="log-round" style="color:#ff3300">> FAULT INJECTION INITIATED</div>`);
        logCallback(`<div class="log-phase">⚡ Injecting bitflip at Round ${faultRound}, Nibble ${faultNibble}</div>`);
        logCallback(`<div class="log-data">Fault: Δ = 0x${faultValue.toString(16)} (single bit flip)</div>`);
        logCallback(`<div class="log-data">Location: Before S-box in DEFAULT-LAYER (LS S-box)</div>`);

        faultVFXCallback(faultNibble);

        const result = sim.encryptWithFault(ptHex, faultRound, faultNibble, faultValue);

        logCallback(`<div class="log-data">Faulty ciphertext C' = ${result.ciphertext}</div>`);

        // Show differential
        const diff = sim.computeDifferential(sim.correctCiphertext, result.ciphertext);
        const diffHex = sim.getDifferentialHex(diff);
        const activeNibbles = diff.filter(d => d !== 0).length;

        logCallback(`<div class="log-phase">Computing Differential ΔC = C ⊕ C'</div>`);
        logCallback(`<div class="log-data">ΔC = ${diffHex}</div>`);
        logCallback(`<div class="log-highlight">+ ${activeNibbles}/32 nibbles show differences (fault diffusion)</div>`);

        showDifferential(sim.correctCiphertext, result.ciphertext, diff);
        sim.differentials.push({ diff, diffHex, activeNibbles });

        return { diff, faultyCt: result.ciphertext, activeNibbles };
    }

    function executeStep4_DifferentialAnalysis() {
        updatePhaseTracker(3);
        logCallback(`<br><div class="log-round" style="color:#ff6600">> DIFFERENTIAL FAULT ANALYSIS</div>`);
        logCallback(`<div class="log-phase">Filtering key candidates using DDT of LS S-box...</div>`);

        const results = sim.performSingleRoundDFA(sim.correctCiphertext, sim.faultyCiphertexts[0]);

        let filtered = 0;
        let totalRemaining = 0;
        results.forEach(r => {
            if (r.filtered) {
                filtered++;
                logCallback(`<div class="log-data">Nibble ${31 - r.nibble}: ΔOut=0x${r.deltaOut.toString(16)} → ${r.candidates.length} candidates [${r.candidates.map(c => c.toString(16)).join(',')}]</div>`);
            }
            totalRemaining += r.candidates.length;
        });

        logCallback(`<br><div class="log-phase">DFA Results:</div>`);
        logCallback(`<div class="log-data">${filtered}/32 nibbles filtered by differential</div>`);
        logCallback(`<div class="log-highlight">+ Key space: 2¹²⁸ → 2⁶⁴ (${AttackEngine.formatKeySpace(sim.keySpaceBits)})</div>`);
        logCallback(`<div class="log-data">Each LS S-box nibble retains 4 candidates due to linear structures</div>`);

        updateKeySpaceGauge(sim.keySpaceBits);
        updateNibbleGrid(sim.nibbleCandidates.map(c => [...c]));

        return results;
    }

    function executeStep5_EquivalentKeys() {
        updatePhaseTracker(4);
        const classes = sim.extractEquivalentClasses();

        logCallback(`<br><div class="log-round" style="color:#ff9900">> EQUIVALENT KEY CLASSES</div>`);
        logCallback(`<div class="log-phase">Linear structures of S_LS create indistinguishable keys:</div>`);

        showLinearStructures();

        for (let i = 0; i < 4; i++) {
            const cls = classes[i];
            logCallback(`<div class="log-data">Nibble ${31-i}: True key=0x${cls.trueKey.toString(16)} → Equiv: {${cls.equivalentKeys.map(k => k.toString(16)).join(', ')}}</div>`);
        }
        logCallback(`<div class="log-data">... (32 nibbles total, each with 4 equivalent keys)</div>`);
        logCallback(`<div class="log-highlight">+ ∀ nibble: k, k⊕0xa, k⊕0xf, k⊕0x5 produce identical ciphertext differences</div>`);
        logCallback(`<div class="log-highlight">+ This is the fundamental barrier: 4³² = 2⁶⁴ keys are indistinguishable per round</div>`);

        return classes;
    }

    function executeStep6_NormalizedKeys() {
        updatePhaseTracker(5);
        const normInfo = sim.computeNormalizedKey();

        logCallback(`<br><div class="log-round ls">> NORMALIZED KEY EXTRACTION</div>`);
        logCallback(`<div class="log-phase">Selecting canonical representatives from each equivalence class:</div>`);
        logCallback(`<div class="log-data">Normalization: K̄ = A_{K→N} · K (linear operation over F₂)</div>`);

        let normHex = '';
        for (let i = 31; i >= 0; i--) normHex += normInfo[i].normalized.toString(16);

        for (let i = 0; i < 4; i++) {
            const info = normInfo[i];
            logCallback(`<div class="log-data">N${31-i}: {${info.equivClass.map(v => v.toString(16)).join(',')}} → K̄=${info.normalized.toString(16)}</div>`);
        }
        logCallback(`<div class="log-data">...</div>`);
        logCallback(`<div class="log-highlight">+ Normalized key K̄ = ${normHex}</div>`);
        logCallback(`<div class="log-data">Each normalized nibble uses only 2 bits → unique recovery possible</div>`);
        logCallback(`<div class="log-phase">Key insight: For n round keys, n-1 normalized keys are uniquely recoverable</div>`);

        return normInfo;
    }

    function executeStep7_InformationCombining(subStep) {
        updatePhaseTracker(6);
        const result = sim.simulateInformationCombining(subStep);

        const labels = [
            "Single-round DFA on 6 consecutive round keys",
            "Convert normalized-key equations to full key space",
            "Add key schedule constraints: K₀=K₄, K₁=K₅",
            "Add normalization constraints: (K₀..K₃) ∈ N⁽⁴⁾",
            "Solve full-rank linear system → UNIQUE KEY"
        ];

        logCallback(`<br><div class="log-round" style="color:#ff3366">> IC STEP ${subStep + 1}/5: ${labels[subStep]}</div>`);
        logCallback(`<div class="log-data">Faults injected: ${result.faultCount} | Eq. rank: ${result.equationRank}/768</div>`);
        logCallback(`<div class="log-highlight">+ Key space: ${AttackEngine.formatKeySpace(result.keySpaceBits)}</div>`);

        if (subStep >= 2) {
            faultVFXCallback(Math.floor(Math.random() * 16));
        }

        updateKeySpaceGauge(result.keySpaceBits);
        updateNibbleGrid(result.nibbleCandidates);
        updateEquationPanel(result.equationRank, result.totalEquations);

        return result;
    }

    function executeStep8_KeyRecovery() {
        updatePhaseTracker(7);
        const result = sim.recoverKey();

        logCallback(`<br><div class="log-round" style="color:#00ff66">> ████ FULL KEY RECOVERY SUCCESS ████</div>`);
        logCallback(`<div class="log-phase" style="color:#00ff66">The 128-bit master key has been algebraically recovered!</div>`);
        logCallback(`<div class="log-highlight">Recovered Key: ${result.recoveredKey}</div>`);
        logCallback(`<div class="log-highlight">Verification: ${result.matches ? '✓ MATCH CONFIRMED' : '✗ MISMATCH'}</div>`);
        logCallback(`<br><div class="log-phase">Attack Summary:</div>`);
        logCallback(`<div class="log-data">• Method: Information-Combining NK-DFA (Eurocrypt 2022)</div>`);
        logCallback(`<div class="log-data">• Faults required: ~16 (optimized)</div>`);
        logCallback(`<div class="log-data">• Key space collapsed: 2¹²⁸ → 1</div>`);
        logCallback(`<div class="log-data">• Bypasses: LS S-box DFA resilience claim of 2⁶⁴</div>`);
        logCallback(`<div class="log-data">• Exploits: Linear structures + key schedule + normalization</div>`);

        updateKeySpaceGauge(0);
        updateNibbleGrid(sim.nibbleCandidates.map(c => [...c]));
        updateEquationPanel(768, 1024);

        return result;
    }

    function getSimulation() { return sim; }
    function cleanup() { if (atkAnimState.timer) clearInterval(atkAnimState.timer); }

    return {
        init, reset, cleanup, getSimulation,
        updateKeySpaceGauge, updateNibbleGrid, updateEquationPanel, updatePhaseTracker,
        showDifferential, showLinearStructures,
        executeStep1_Setup, executeStep2_Encrypt, executeStep3_FaultInjection,
        executeStep4_DifferentialAnalysis, executeStep5_EquivalentKeys,
        executeStep6_NormalizedKeys, executeStep7_InformationCombining,
        executeStep8_KeyRecovery, atkAnimState
    };
})();
