'use strict';
/*
 * echo-sub: removes the voices this tab plays from the captured system audio of a screen share.
 *
 * input 0: captured screen audio (stereo) = game/music + g * (our playback of other people's voices), delayed
 * input 1: reference = the same voices, mixed with the same per-person volumes (mono)
 * output : captured audio with the voice estimate subtracted
 *
 * The echo path is digital (OS loopback), so it is linear: a delay + gain + resampler low-pass.
 *   1. coarse delay: GCC-PHAT cross-correlation on 4x-decimated signals, re-estimated every ~0.25 s
 *   2. fine path:    least-squares FIR (M taps) around that delay. Correlations are accumulated with ~4 s
 *                    forgetting while voices are active and solved exactly (Levinson, Toeplitz). Game/music
 *                    is uncorrelated with the voices, so it averages out: no step size to tune.
 *   3. safety:       subtraction is applied only while it measurably lowers the energy (never makes it worse).
 * The capture is delayed by PRE samples so slightly "negative" delays are still causal.
 */

const PRE = 1024;          // capture pre-delay, samples (~21 ms @48k)
const M = 48;              // FIR taps (~1 ms): the loopback path is short (delay + gain + resampler)
const C = 16;              // taps before the estimated delay (the window re-centres on the actual peak)
const DEC = 4;             // decimation for delay search
const W = 4096;            // correlation window (decimated samples) ~0.34 s
const LMAX = 4096;         // max delay searched (decimated) ~0.34 s
const P = PRE / DEC;       // negative-lag margin (decimated)
const FFTN = 16384;
const RN = 1 << 16;        // raw rings (~1.36 s)
const DN = 1 << 14;        // decimated rings
const ZERO = new Float32Array(128);

function fft(re, im, inv) {
  const n = re.length;
  for (let i = 1, j = 0; i < n; i++) {
    let bit = n >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j ^= bit;
    if (i < j) { let t = re[i]; re[i] = re[j]; re[j] = t; t = im[i]; im[i] = im[j]; im[j] = t; }
  }
  for (let len = 2; len <= n; len <<= 1) {
    const ang = (inv ? 2 : -2) * Math.PI / len;
    const wr = Math.cos(ang), wi = Math.sin(ang);
    const half = len >> 1;
    for (let i = 0; i < n; i += len) {
      let cr = 1, ci = 0;
      for (let k = 0; k < half; k++) {
        const a = i + k, b = a + half;
        const xr = re[b] * cr - im[b] * ci, xi = re[b] * ci + im[b] * cr;
        re[b] = re[a] - xr; im[b] = im[a] - xi;
        re[a] += xr; im[a] += xi;
        const ncr = cr * wr - ci * wi; ci = cr * wi + ci * wr; cr = ncr;
      }
    }
  }
}

/** solve Toeplitz(r) x = b for symmetric r (Levinson recursion). false if ill-conditioned. */
function levinson(r, b, x, f, bw, tmp, n) {
  if (!(r[0] > 0)) return false;
  f[0] = 1 / r[0]; bw[0] = f[0]; x[0] = b[0] / r[0];
  for (let m = 1; m < n; m++) {
    let ef = 0, ex = 0;
    for (let i = 0; i < m; i++) { ef += r[m - i] * f[i]; ex += r[m - i] * x[i]; }
    const den = 1 - ef * ef;
    if (!(den > 1e-12)) return false;
    // f' = ([f;0] - ef*[0;bw]) / den ; bw' = reverse(f')
    for (let i = 0; i <= m; i++) {
      const fi = i < m ? f[i] : 0, bi = i > 0 ? bw[i - 1] : 0;
      tmp[i] = (fi - ef * bi) / den;
    }
    for (let i = 0; i <= m; i++) f[i] = tmp[i];
    for (let i = 0; i <= m; i++) bw[i] = f[m - i];
    const k = b[m] - ex;
    x[m] = 0;
    for (let i = 0; i <= m; i++) x[i] += k * bw[i];
  }
  return true;
}

class EchoSub extends AudioWorkletProcessor {
  constructor() {
    super();
    this.ref = new Float32Array(RN);
    this.cl = new Float32Array(RN);
    this.cr = new Float32Array(RN);
    this.dref = new Float32Array(DN);
    this.dcap = new Float32Array(DN);
    this.t = 0; this.dt = 0; this.accR = 0; this.accC = 0;
    this.w = new Float64Array(M);
    this.rxx = new Float64Array(M);   // autocorrelation of the reference
    this.pxc = new Float64Array(M);   // cross-correlation reference -> capture
    this.lam = 1 - 1 / (sampleRate * 4);      // correlation memory (voice-active time)
    this.lamS = 1 - 1 / (sampleRate * 0.3);   // safety-switch memory
    this.sx = new Float64Array(M); this.sf = new Float64Array(M); this.sb = new Float64Array(M);
    this.st = new Float64Array(M); this.rl = new Float64Array(M);
    this.lag = 0; this.haveLag = false; this.cand = null;
    this.active = 0;
    this.sinceSolve = 0;
    this.refE = 0;
    this.lastEst = 0; this.conf = 0;
    this.ein = 0; this.eout = 0; this.apply = false;
    this.rIn = 0; this.rOut = 0; this.lastReport = 0;
    this.enabled = true;
    this.ar = new Float64Array(FFTN); this.ai = new Float64Array(FFTN);
    this.br = new Float64Array(FFTN); this.bi = new Float64Array(FFTN);
    this.port.onmessage = e => { if (e.data && 'enabled' in e.data) this.enabled = !!e.data.enabled; };
  }

  resetFilter() {
    this.w.fill(0); this.rxx.fill(0); this.pxc.fill(0);
    this.active = 0; this.apply = false; this.ein = 0; this.eout = 0;
  }

  /** move the tap window by s samples (positive = longer delay), keeping what was learned */
  shift(s) {
    const np = new Float64Array(M), nw = new Float64Array(M);
    for (let k = 0; k < M; k++) { const j = k + s; if (j >= 0 && j < M) { np[k] = this.pxc[j]; nw[k] = this.w[j]; } }
    this.pxc = np; this.w = nw; this.lag += s;
  }

  solve() {
    const rl = this.rl;
    for (let k = 0; k < M; k++) rl[k] = this.rxx[k];
    rl[0] = this.rxx[0] * 1.002 + 1e-9; // diagonal loading
    if (!levinson(rl, this.pxc, this.sx, this.sf, this.sb, this.st, M)) return;
    let en = 0; for (let k = 0; k < M; k++) en += this.sx[k] * this.sx[k];
    if (!(en < 16)) return; // absurd gain → ignore
    for (let k = 0; k < M; k++) this.w[k] = this.sx[k];
    // re-centre the window on the actual peak
    let pk = 0, pv = 0; for (let k = 0; k < M; k++) if (Math.abs(this.w[k]) > pv) { pv = Math.abs(this.w[k]); pk = k; }
    if (this.active > sampleRate * 0.5 && Math.abs(pk - C) > 3) this.shift(pk - C);
  }

  estimate() {
    const T = this.dt, capEnd = T - P;
    const ar = this.ar, ai = this.ai, br = this.br, bi = this.bi;
    ar.fill(0); ai.fill(0); br.fill(0); bi.fill(0);
    for (let i = 0; i < W; i++) ar[i] = this.dcap[(capEnd - W + i) & (DN - 1)];
    const rl = W + LMAX + P;
    for (let j = 0; j < rl; j++) br[j] = this.dref[(capEnd - W - LMAX + j) & (DN - 1)];
    fft(ar, ai, false); fft(br, bi, false);
    // conj(A) * B, PHAT-weighted (whitening: robust when music dominates the capture)
    for (let k = 0; k < FFTN; k++) {
      const zr = ar[k] * br[k] + ai[k] * bi[k];
      const zi = ar[k] * bi[k] - ai[k] * br[k];
      const m = Math.hypot(zr, zi) + 1e-12;
      ar[k] = zr / m; ai[k] = zi / m;
    }
    fft(ar, ai, true);
    let best = -Infinity, bs = 0, sum = 0;
    const smax = LMAX + P;
    for (let s = 0; s <= smax; s++) { const v = ar[s]; sum += Math.abs(v); if (v > best) { best = v; bs = s; } }
    const conf = best / (sum / (smax + 1) + 1e-12);
    this.conf = conf;
    if (conf < 7) return;
    const lagRaw = (LMAX - bs) * DEC;
    if (this.cand !== null && Math.abs(this.cand - lagRaw) <= 2 * DEC) {
      if (!this.haveLag) { this.lag = lagRaw; this.haveLag = true; this.resetFilter(); }
      else if (Math.abs(lagRaw - this.lag) > M / 2) { this.lag = lagRaw; this.resetFilter(); }
      // small differences are handled by solve() re-centring on the fine peak
    }
    this.cand = lagRaw;
  }

  process(inputs, outputs) {
    const cap = inputs[0] || [], refIn = inputs[1] || [];
    const out = outputs[0];
    const n = out[0].length;
    const L = cap[0] || ZERO, R = cap[1] || cap[0] || ZERO, X = refIn[0] || ZERO;
    const ref = this.ref;
    for (let i = 0; i < n; i++) {
      const t = this.t;
      const r = X[i] || 0;
      ref[t & (RN - 1)] = r;
      this.cl[t & (RN - 1)] = L[i] || 0;
      this.cr[t & (RN - 1)] = R[i] || 0;
      this.accR += r; this.accC += ((L[i] || 0) + (R[i] || 0)) * 0.5;
      if ((t & (DEC - 1)) === DEC - 1) {
        this.dref[this.dt & (DN - 1)] = this.accR / DEC;
        this.dcap[this.dt & (DN - 1)] = this.accC / DEC;
        this.dt++; this.accR = 0; this.accC = 0;
      }
      this.refE = this.refE * 0.999 + r * r * 0.001;

      const td = t - PRE;
      let lc = this.cl[td & (RN - 1)], rc = this.cr[td & (RN - 1)];
      if (this.haveLag) {
        const base = td - (this.lag - C);
        const w = this.w, rxx = this.rxx, pxc = this.pxc;
        const mc = (lc + rc) * 0.5;
        let y = 0;
        for (let k = 0; k < M; k++) y += w[k] * ref[(base - k) & (RN - 1)];
        if (this.refE > 1e-7) {
          // accumulate only while someone talks (silence would just erase the memory)
          const lam = this.lam, x0 = ref[base & (RN - 1)];
          for (let k = 0; k < M; k++) {
            const xk = ref[(base - k) & (RN - 1)];
            pxc[k] = lam * pxc[k] + xk * mc;
            rxx[k] = lam * rxx[k] + x0 * xk;
          }
          this.active++;
          if (++this.sinceSolve >= 2048) { this.sinceSolve = 0; this.solve(); }
          const e = mc - y;
          // subtracting y lowers the energy iff 2*E[mc*y] > E[y^2]; music is uncorrelated with y and averages out
          const ls = this.lamS;
          this.ein = this.ein * ls + mc * y; this.eout = this.eout * ls + y * y;
          if (this.active > sampleRate * 0.3) {
            const ok = 2 * this.ein > 1.1 * this.eout;
            // the path changed (e.g. browser volume in the OS mixer): we'd over-subtract → relearn from scratch
            if (this.apply && 2 * this.ein < 0.9 * this.eout) { this.resetFilter(); }
            else this.apply = ok;
          }
          this.rIn += mc * mc; this.rOut += this.apply ? e * e : mc * mc;
        }
        if (this.enabled && this.apply) { lc -= y; rc -= y; }
      }
      out[0][i] = lc;
      if (out[1]) out[1][i] = rc;
      this.t++;
    }
    if (this.dt - this.lastEst > 3000 && this.refE > 1e-6) { this.lastEst = this.dt; this.estimate(); }
    if (this.t - this.lastReport > sampleRate) {
      this.lastReport = this.t;
      const red = this.rOut > 0 ? 10 * Math.log10(this.rIn / this.rOut) : 0;
      let pk = 0, pv = 0; for (let k = 0; k < M; k++) if (Math.abs(this.w[k]) > Math.abs(pv)) { pv = this.w[k]; pk = k; }
      this.port.postMessage({ pk, pv, apply: this.apply, lagMs: this.haveLag ? this.lag / sampleRate * 1000 : null, conf: this.conf, reduction: red });
      this.rIn = 0; this.rOut = 0;
    }
    return true;
  }
}

registerProcessor('echo-sub', EchoSub);
