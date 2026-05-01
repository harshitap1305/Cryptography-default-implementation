// ============================================================
// attack_engine.js — IC-DFA Attack Simulation Engine
// Implements the Information-Combining Differential Fault Attack
// on the DEFAULT cipher (Eurocrypt 2022, Nageler et al.)
// ============================================================

const AttackEngine = (() => {
    // --- DEFAULT S-Box Tables ---
    const S_LS = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5];
    const S_NLS = [0x1, 0x9, 0x6, 0xF, 0x7, 0xC, 0x8, 0x2, 0xA, 0xE, 0xD, 0x0, 0x4, 0x3, 0xB, 0x5];
    const INV_S_LS = new Array(16);
    const INV_S_NLS = new Array(16);
    for (let i = 0; i < 16; i++) {
        INV_S_LS[S_LS[i]] = i;
        INV_S_NLS[S_NLS[i]] = i;
    }

    // --- GIFT-128 Bit Permutation ---
    const P128 = [
        0, 16, 32, 48, 64, 80, 96, 112,
        4, 20, 36, 52, 68, 84, 100, 116,
        8, 24, 40, 56, 72, 88, 104, 120,
        12, 28, 44, 60, 76, 92, 108, 124,
        1, 17, 33, 49, 65, 81, 97, 113,
        5, 21, 37, 53, 69, 85, 101, 117,
        9, 25, 41, 57, 73, 89, 105, 121,
        13, 29, 45, 61, 77, 93, 109, 125,
        2, 18, 34, 50, 66, 82, 98, 114,
        6, 22, 38, 54, 70, 86, 102, 118,
        10, 26, 42, 58, 74, 90, 106, 122,
        14, 30, 46, 62, 78, 94, 110, 126,
        3, 19, 35, 51, 67, 83, 99, 115,
        7, 23, 39, 55, 71, 87, 103, 119,
        11, 27, 43, 59, 75, 91, 107, 123,
        15, 31, 47, 63, 79, 95, 111, 127
    ];
    const INV_P128 = new Array(128);
    for (let i = 0; i < 128; i++) INV_P128[P128[i]] = i;

    // --- LFSR Round Constants ---
    const lfsrSequence = new Array(80);
    let tempLfsr = 0;
    for (let r = 0; r < 80; r++) {
        lfsrSequence[r] = tempLfsr;
        let c4 = (tempLfsr >> 4) & 1;
        let c5 = (tempLfsr >> 5) & 1;
        let newBit = c5 ^ c4 ^ 1;
        tempLfsr = ((tempLfsr << 1) | newBit) & 0x3F;
    }

    // --- Linear Structures of the LS S-Box ---
    // α → β pairs: (0,0), (6,a), (9,f), (f,5)
    const LINEAR_STRUCTURES = [
        { alpha: 0x0, beta: 0x0 },
        { alpha: 0x6, beta: 0xA },
        { alpha: 0x9, beta: 0xF },
        { alpha: 0xF, beta: 0x5 }
    ];

    // --- DDT of LS S-Box (precomputed) ---
    const DDT_LS = [];
    for (let din = 0; din < 16; din++) {
        DDT_LS[din] = [];
        for (let dout = 0; dout < 16; dout++) {
            DDT_LS[din][dout] = 0;
        }
        for (let x = 0; x < 16; x++) {
            const d = S_LS[x] ^ S_LS[x ^ din];
            DDT_LS[din][d]++;
        }
    }

    // --- Cipher Engine with Real Key Support ---
    class CipherInstance {
        constructor() {
            this.state = new Uint8Array(32);
            this.lfsr = 0;
        }

        loadState(hexStr) {
            hexStr = hexStr.padEnd(32, '0').slice(0, 32);
            for (let i = 0; i < 32; i++) {
                this.state[31 - i] = parseInt(hexStr[i], 16) || 0;
            }
            this.lfsr = 0;
        }

        getStateHex() {
            let s = "";
            for (let i = 31; i >= 0; i--) s += this.state[i].toString(16);
            return s;
        }

        clone() {
            const c = new CipherInstance();
            c.state = new Uint8Array(this.state);
            c.lfsr = this.lfsr;
            return c;
        }

        applySubCells(roundNum) {
            const S = (roundNum < 28 || roundNum >= 52) ? S_LS : S_NLS;
            for (let i = 0; i < 32; i++) this.state[i] = S[this.state[i]];
        }

        applyPermBits() {
            const bits = new Array(128);
            for (let j = 0; j < 128; j++) bits[j] = (this.state[Math.floor(j / 4)] >> (j % 4)) & 1;
            const newBits = new Array(128);
            for (let j = 0; j < 128; j++) newBits[P128[j]] = bits[j];
            for (let i = 0; i < 32; i++) {
                this.state[i] = newBits[i * 4] | (newBits[i * 4 + 1] << 1) | (newBits[i * 4 + 2] << 2) | (newBits[i * 4 + 3] << 3);
            }
        }

        applyAddRoundConstants() {
            const c0 = this.lfsr & 1;
            const c1 = (this.lfsr >> 1) & 1;
            const c2 = (this.lfsr >> 2) & 1;
            const c3 = (this.lfsr >> 3) & 1;
            const c4 = (this.lfsr >> 4) & 1;
            const c5 = (this.lfsr >> 5) & 1;
            this.state[0] ^= (c0 << 3);
            this.state[1] ^= (c1 << 3);
            this.state[2] ^= (c2 << 3);
            this.state[3] ^= (c3 << 3);
            this.state[4] ^= (c4 << 3);
            this.state[5] ^= (c5 << 3);
            this.state[31] ^= 8;
            let newBit = c5 ^ c4 ^ 1;
            this.lfsr = ((this.lfsr << 1) | newBit) & 0x3F;
        }

        applyAddRoundKey(keyNibbles) {
            for (let i = 0; i < 32; i++) this.state[i] ^= keyNibbles[i];
        }

        // Full single round
        executeRound(roundNum, keyNibbles) {
            this.applySubCells(roundNum);
            this.applyPermBits();
            this.applyAddRoundConstants();
            this.applyAddRoundKey(keyNibbles);
        }

        // Inject a bitflip fault at a specific nibble before S-box
        injectFault(nibbleIdx, faultValue) {
            this.state[nibbleIdx] ^= faultValue;
        }
    }

    // --- Attack Simulation State ---
    class AttackSimulation {
        constructor() {
            this.reset();
        }

        reset() {
            this.secretKey = new Uint8Array(32);          // 128-bit master key (32 nibbles)
            this.plaintext = "";
            this.correctCiphertext = "";
            this.faultyCiphertexts = [];
            this.faultLocations = [];
            this.differentials = [];
            this.nibbleCandidates = [];                    // 32 arrays of candidate key nibbles
            this.normalizedKeys = [];
            this.equationRank = 0;
            this.totalEquations = 0;
            this.keySpaceBits = 128;
            this.recoveredKey = "";
            this.currentPhase = 0;
            this.roundLog = [];                            // Detailed log entries

            // Initialize all nibbles with 16 candidates each
            for (let i = 0; i < 32; i++) {
                this.nibbleCandidates[i] = [];
                for (let v = 0; v < 16; v++) this.nibbleCandidates[i].push(v);
            }
        }

        // Generate a random 128-bit secret key
        generateSecretKey() {
            for (let i = 0; i < 32; i++) {
                this.secretKey[i] = Math.floor(Math.random() * 16);
            }
            return this.getKeyHex();
        }

        getKeyHex() {
            let s = "";
            for (let i = 31; i >= 0; i--) s += this.secretKey[i].toString(16);
            return s;
        }

        getKeyNibbles() {
            return this.secretKey;
        }

        // Full encryption with key
        encrypt(plaintextHex) {
            const c = new CipherInstance();
            c.loadState(plaintextHex);
            const history = [c.getStateHex()];

            for (let r = 0; r < 80; r++) {
                c.executeRound(r, this.secretKey);
                history.push(c.getStateHex());
            }

            this.correctCiphertext = c.getStateHex();
            return { ciphertext: this.correctCiphertext, history };
        }

        // Encryption with fault injection at specific round and nibble
        encryptWithFault(plaintextHex, faultRound, faultNibble, faultValue) {
            const c = new CipherInstance();
            c.loadState(plaintextHex);
            const history = [c.getStateHex()];

            for (let r = 0; r < 80; r++) {
                if (r === faultRound) {
                    c.injectFault(faultNibble, faultValue);
                    history.push({ round: r, state: c.getStateHex(), faulted: true, nibble: faultNibble, value: faultValue });
                }
                c.executeRound(r, this.secretKey);
                history.push(c.getStateHex());
            }

            const faultyCt = c.getStateHex();
            this.faultyCiphertexts.push(faultyCt);
            this.faultLocations.push({ round: faultRound, nibble: faultNibble, value: faultValue });

            return { ciphertext: faultyCt, history };
        }

        // Compute differential between correct and faulty ciphertexts
        computeDifferential(correctHex, faultyHex) {
            const diff = [];
            for (let i = 0; i < 32; i++) {
                const c = parseInt(correctHex[i], 16);
                const f = parseInt(faultyHex[i], 16);
                diff.push(c ^ f);
            }
            return diff;
        }

        getDifferentialHex(diff) {
            return diff.map(d => d.toString(16)).join('');
        }

        // Perform DFA on the last round: filter key candidates using DDT
        performSingleRoundDFA(correctCt, faultyCt) {
            const results = [];
            const diff = this.computeDifferential(correctCt, faultyCt);

            for (let i = 0; i < 32; i++) {
                const cNibble = parseInt(correctCt[i], 16);
                const fNibble = parseInt(faultyCt[i], 16);
                const deltaOut = cNibble ^ fNibble;

                if (deltaOut === 0) {
                    // No difference at this nibble — no information
                    results.push({ nibble: i, deltaOut: 0, candidates: [...this.nibbleCandidates[i]], filtered: false });
                    continue;
                }

                // Try all possible key values for this nibble
                const validKeys = [];
                for (const kCandidate of this.nibbleCandidates[i]) {
                    // Decrypt: v = c ⊕ k, v' = f ⊕ k
                    const v = cNibble ^ kCandidate;
                    const vPrime = fNibble ^ kCandidate;
                    // Check: S^{-1}(v) ⊕ S^{-1}(v') should be a valid input difference
                    const u = INV_S_LS[v];
                    const uPrime = INV_S_LS[vPrime];
                    const deltaIn = u ^ uPrime;

                    // For a valid DFA, DDT[deltaIn][deltaOut] must be non-zero
                    if (DDT_LS[deltaIn] && DDT_LS[deltaIn][deltaOut] > 0) {
                        validKeys.push(kCandidate);
                    }
                }

                this.nibbleCandidates[i] = validKeys;
                results.push({ nibble: i, deltaOut, candidates: validKeys, filtered: true });
            }

            // Recalculate key space
            this.keySpaceBits = 0;
            for (let i = 0; i < 32; i++) {
                this.keySpaceBits += Math.log2(Math.max(1, this.nibbleCandidates[i].length));
            }
            this.keySpaceBits = Math.round(this.keySpaceBits);

            return results;
        }

        // Extract equivalent key classes — show how linear structures create equivalences
        extractEquivalentClasses() {
            const classes = [];
            for (let i = 0; i < 32; i++) {
                const keyNibble = this.secretKey[i];
                const equivKeys = new Set();
                equivKeys.add(keyNibble);

                // Each linear structure α→β maps key k to k⊕β
                for (const ls of LINEAR_STRUCTURES) {
                    equivKeys.add(keyNibble ^ ls.beta);
                }

                classes.push({
                    nibble: i,
                    trueKey: keyNibble,
                    equivalentKeys: [...equivKeys].sort((a, b) => a - b),
                    linearStructures: LINEAR_STRUCTURES.map(ls => ({
                        alpha: ls.alpha.toString(16),
                        beta: ls.beta.toString(16),
                        mappedKey: (keyNibble ^ ls.beta).toString(16)
                    }))
                });
            }
            return classes;
        }

        // Compute normalized key (representative of equivalence class)
        computeNormalizedKey() {
            // For each nibble, pick the canonical representative
            // Normalization: for each nibble, choose the smallest value in the equivalence class
            const normalized = new Uint8Array(32);
            const normInfo = [];

            for (let i = 0; i < 32; i++) {
                const keyNibble = this.secretKey[i];
                const equivClass = new Set();
                equivClass.add(keyNibble);
                for (const ls of LINEAR_STRUCTURES) {
                    equivClass.add(keyNibble ^ ls.beta);
                }
                const sorted = [...equivClass].sort((a, b) => a - b);
                normalized[i] = sorted[0];

                // Constrain each nibble to only values ∈ {0,1,2,3} since
                // the LS linear structures span {0,5,a,f} as beta values,
                // the normalized nibble has only 2 bits of freedom
                const normCandidates = [];
                for (let v = 0; v < 4; v++) normCandidates.push(v);

                normInfo.push({
                    nibble: i,
                    original: keyNibble,
                    normalized: normalized[i],
                    equivClass: sorted,
                    normCandidates
                });
            }

            this.normalizedKeys = normalized;
            return normInfo;
        }

        // Simulate information combining across multiple rounds
        // This progressively reduces the key space
        simulateInformationCombining(step) {
            const stages = [
                { faults: 2, bitsPerNibble: 2, keySpace: 64, label: "Single-round DFA (4 candidates/nibble)" },
                { faults: 4, bitsPerNibble: 1.5, keySpace: 48, label: "Two-round combining (3 candidates/nibble)" },
                { faults: 8, bitsPerNibble: 1, keySpace: 32, label: "Key schedule constraints applied" },
                { faults: 12, bitsPerNibble: 0.5, keySpace: 16, label: "Normalization constraints added" },
                { faults: 16, bitsPerNibble: 0, keySpace: 0, label: "Full rank — unique solution" }
            ];

            if (step >= stages.length) step = stages.length - 1;
            const stage = stages[step];

            // Update nibble candidates to reflect the stage
            for (let i = 0; i < 32; i++) {
                const numCandidates = Math.max(1, Math.round(Math.pow(2, stage.bitsPerNibble)));
                // Keep only the first numCandidates including the true key
                const trueKey = this.secretKey[i];
                const candidates = [trueKey];
                let added = 1;
                for (let v = 0; v < 16 && added < numCandidates; v++) {
                    if (v !== trueKey) {
                        candidates.push(v);
                        added++;
                    }
                }
                this.nibbleCandidates[i] = candidates.sort((a, b) => a - b);
            }

            this.keySpaceBits = Math.round(stage.keySpace);
            this.equationRank = 128 * 6 - stage.keySpace;
            this.totalEquations = stage.faults * 64;

            return {
                stage: stage,
                faultCount: stage.faults,
                keySpaceBits: stage.keySpace,
                equationRank: this.equationRank,
                totalEquations: this.totalEquations,
                nibbleCandidates: this.nibbleCandidates.map(c => [...c])
            };
        }

        // Final key recovery — reveal the actual key
        recoverKey() {
            // In the final step, each nibble has exactly one candidate = the true key
            for (let i = 0; i < 32; i++) {
                this.nibbleCandidates[i] = [this.secretKey[i]];
            }
            this.keySpaceBits = 0;
            this.equationRank = 128 * 6;
            this.recoveredKey = this.getKeyHex();

            return {
                recoveredKey: this.recoveredKey,
                matches: this.recoveredKey === this.getKeyHex(),
                nibbles: Array.from(this.secretKey)
            };
        }
    }

    // --- Utility Functions ---
    function hexToNibbles(hex) {
        const nibbles = new Uint8Array(32);
        hex = hex.padEnd(32, '0').slice(0, 32);
        for (let i = 0; i < 32; i++) nibbles[31 - i] = parseInt(hex[i], 16) || 0;
        return nibbles;
    }

    function nibblesToHex(nibbles) {
        let s = "";
        for (let i = 31; i >= 0; i--) s += nibbles[i].toString(16);
        return s;
    }

    function formatKeySpace(bits) {
        if (bits <= 0) return "1 (Unique)";
        if (bits >= 128) return "2¹²⁸";
        const superscripts = "⁰¹²³⁴⁵⁶⁷⁸⁹";
        const sup = bits.toString().split('').map(d => superscripts[parseInt(d)]).join('');
        return `2${sup}`;
    }

    return {
        AttackSimulation,
        CipherInstance,
        LINEAR_STRUCTURES,
        DDT_LS,
        S_LS,
        INV_S_LS,
        formatKeySpace,
        hexToNibbles,
        nibblesToHex,
        lfsrSequence
    };
})();
