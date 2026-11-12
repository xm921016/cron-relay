(function(nacl) {
'use strict';

// Ported in 2014 by Dmitry Chestnykh and Devi Mandiri.
// Public domain.
//
// Implementation derived from TweetNaCl version 20140427.
// See for details: http://tweetnacl.cr.yp.to/

var u64 = function(h, l) { this.hi = h|0 >>> 0; this.lo = l|0 >>> 0; };
var gf = function(init) {
  var i, r = new Float64Array(16);
  if (init) for (i = 0; i < init.length; i++) r[i] = init[i];
  return r;
};

//  Pluggable, initialized in high-level API below.
var randombytes = function(/* x, n */) { throw new Error('no PRNG'); };

var _0 = new Uint8Array(16);
var _9 = new Uint8Array(32); _9[0] = 9;

var gf0 = gf(),
    gf1 = gf([1]),
    _121665 = gf([0xdb41, 1]),
    D = gf([0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203]),
    D2 = gf([0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406]),
    X = gf([0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169]),
    Y = gf([0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666]),
    I = gf([0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83]);

function L32(x, c) { return (x << c) | (x >>> (32 - c)); }

function ld32(x, i) {
  var u = x[i+3] & 0xff;
  u = (u<<8)|(x[i+2] & 0xff);
  u = (u<<8)|(x[i+1] & 0xff);
  return (u<<8)|(x[i+0] & 0xff);
}

function dl64(x, i) {
  var h = (x[i] << 24) | (x[i+1] << 16) | (x[i+2] << 8) | x[i+3];
  var l = (x[i+4] << 24) | (x[i+5] << 16) | (x[i+6] << 8) | x[i+7];
  return new u64(h, l);
}

function st32(x, j, u) {
  var i;
  for (i = 0; i < 4; i++) { x[j+i] = u & 255; u >>>= 8; }
}

function ts64(x, i, u) {
  x[i]   = (u.hi >> 24) & 0xff;
  x[i+1] = (u.hi >> 16) & 0xff;
  x[i+2] = (u.hi >>  8) & 0xff;
  x[i+3] = u.hi & 0xff;
  x[i+4] = (u.lo >> 24)  & 0xff;
  x[i+5] = (u.lo >> 16)  & 0xff;
  x[i+6] = (u.lo >>  8)  & 0xff;
  x[i+7] = u.lo & 0xff;
}

function vn(x, xi, y, yi, n) {
  var i,d = 0;
  for (i = 0; i < n; i++) d |= x[xi+i]^y[yi+i];
  return (1 & ((d - 1) >>> 8)) - 1;
}

function crypto_verify_16(x, xi, y, yi) {
  return vn(x,xi,y,yi,16);
}

function crypto_verify_32(x, xi, y, yi) {
  return vn(x,xi,y,yi,32);
}

function core(out,inp,k,c,h) {
  var w = new Uint32Array(16), x = new Uint32Array(16),
      y = new Uint32Array(16), t = new Uint32Array(4);
  var i, j, m;

  for (i = 0; i < 4; i++) {
    x[5*i] = ld32(c, 4*i);
    x[1+i] = ld32(k, 4*i);
    x[6+i] = ld32(inp, 4*i);
    x[11+i] = ld32(k, 16+4*i);
  }

  for (i = 0; i < 16; i++) y[i] = x[i];

  for (i = 0; i < 20; i++) {
    for (j = 0; j < 4; j++) {
      for (m = 0; m < 4; m++) t[m] = x[(5*j+4*m)%16];
      t[1] ^= L32((t[0]+t[3])|0, 7);
      t[2] ^= L32((t[1]+t[0])|0, 9);
      t[3] ^= L32((t[2]+t[1])|0,13);
      t[0] ^= L32((t[3]+t[2])|0,18);
      for (m = 0; m < 4; m++) w[4*j+(j+m)%4] = t[m];
    }
    for (m = 0; m < 16; m++) x[m] = w[m];
  }

  if (h) {
    for (i = 0; i < 16; i++) x[i] = (x[i] + y[i]) | 0;
    for (i = 0; i < 4; i++) {
      x[5*i] = (x[5*i] - ld32(c, 4*i)) | 0;
      x[6+i] = (x[6+i] - ld32(inp, 4*i)) | 0;
    }
    for (i = 0; i < 4; i++) {
      st32(out,4*i,x[5*i]);
      st32(out,16+4*i,x[6+i]);
    }
  } else {
    for (i = 0; i < 16; i++) st32(out, 4 * i, (x[i] + y[i]) | 0);
  }
}

function crypto_core_salsa20(out,inp,k,c) {
  core(out,inp,k,c,false);
  return 0;
}

function crypto_core_hsalsa20(out,inp,k,c) {
  core(out,inp,k,c,true);
  return 0;
}

var sigma = new Uint8Array([101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107]);
            // "expand 32-byte k"

function crypto_stream_salsa20_xor(c,cpos,m,mpos,b,n,k) {
  var z = new Uint8Array(16), x = new Uint8Array(64);
  var u, i;
  if (!b) return 0;
  for (i = 0; i < 16; i++) z[i] = 0;
  for (i = 0; i < 8; i++) z[i] = n[i];
  while (b >= 64) {
    crypto_core_salsa20(x,z,k,sigma);
    for (i = 0; i < 64; i++) c[cpos+i] = (m?m[mpos+i]:0) ^ x[i];
    u = 1;
    for (i = 8; i < 16; i++) {
      u = u + (z[i] & 0xff) | 0;
      z[i] = u & 0xff;
      u >>>= 8;
    }
    b -= 64;
    cpos += 64;
    if (m) mpos += 64;
  }
  if (b > 0) {
    crypto_core_salsa20(x,z,k,sigma);
    for (i = 0; i < b; i++) c[cpos+i] = (m?m[mpos+i]:0) ^ x[i];
  }
  return 0;
}

function crypto_stream_salsa20(c,cpos,d,n,k) {
  return crypto_stream_salsa20_xor(c,cpos,null,0,d,n,k);
}

function crypto_stream(c,cpos,d,n,k) {
  var s = new Uint8Array(32);
  crypto_core_hsalsa20(s,n,k,sigma);
  return crypto_stream_salsa20(c,cpos,d,n.subarray(16),s);
}

function crypto_stream_xor(c,cpos,m,mpos,d,n,k) {
  var s = new Uint8Array(32);
  crypto_core_hsalsa20(s,n,k,sigma);
  return crypto_stream_salsa20_xor(c,cpos,m,mpos,d,n.subarray(16),s);
}

function add1305(h, c) {
  var j, u = 0;
  for (j = 0; j < 17; j++) {
    u = (u + ((h[j] + c[j]) | 0)) | 0;
    h[j] = u & 255;
    u >>>= 8;
  }
}

var minusp = new Uint32Array([
  5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252
]);

function crypto_onetimeauth(out, outpos, m, mpos, n, k) {
  var s, i, j, u;
  var x = new Uint32Array(17), r = new Uint32Array(17),
      h = new Uint32Array(17), c = new Uint32Array(17),
      g = new Uint32Array(17);
  for (j = 0; j < 17; j++) r[j]=h[j]=0;
  for (j = 0; j < 16; j++) r[j]=k[j];
  r[3]&=15;
  r[4]&=252;
  r[7]&=15;
  r[8]&=252;
  r[11]&=15;
  r[12]&=252;
  r[15]&=15;

  while (n > 0) {
    for (j = 0; j < 17; j++) c[j] = 0;
    for (j = 0; (j < 16) && (j < n); ++j) c[j] = m[mpos+j];
    c[j] = 1;
    mpos += j; n -= j;
    add1305(h,c);
    for (i = 0; i < 17; i++) {
      x[i] = 0;
      for (j = 0; j < 17; j++) x[i] = (x[i] + (h[j] * ((j <= i) ? r[i - j] : ((320 * r[i + 17 - j])|0))) | 0) | 0;
    }
    for (i = 0; i < 17; i++) h[i] = x[i];
    u = 0;
    for (j = 0; j < 16; j++) {
      u = (u + h[j]) | 0;
      h[j] = u & 255;
      u >>>= 8;
    }
    u = (u + h[16]) | 0; h[16] = u & 3;
    u = (5 * (u >>> 2)) | 0;
    for (j = 0; j < 16; j++) {
      u = (u + h[j]) | 0;
      h[j] = u & 255;
      u >>>= 8;
    }
    u = (u + h[16]) | 0; h[16] = u;
  }

  for (j = 0; j < 17; j++) g[j] = h[j];
  add1305(h,minusp);
  s = (-(h[16] >>> 7) | 0);
  for (j = 0; j < 17; j++) h[j] ^= s & (g[j] ^ h[j]);

  for (j = 0; j < 16; j++) c[j] = k[j + 16];
  c[16] = 0;
  add1305(h,c);
  for (j = 0; j < 16; j++) out[outpos+j] = h[j];
  return 0;
}

function crypto_onetimeauth_verify(h, hpos, m, mpos, n, k) {
  var x = new Uint8Array(16);
  crypto_onetimeauth(x,0,m,mpos,n,k);
  return crypto_verify_16(h,hpos,x,0);
}

function crypto_secretbox(c,m,d,n,k) {
  var i;
  if (d < 32) return -1;
  crypto_stream_xor(c,0,m,0,d,n,k);
  crypto_onetimeauth(c, 16, c, 32, d - 32, c);
  for (i = 0; i < 16; i++) c[i] = 0;
  return 0;
}

function crypto_secretbox_open(m,c,d,n,k) {
  var i;
  var x = new Uint8Array(32);
  if (d < 32) return -1;
  crypto_stream(x,0,32,n,k);
  if (crypto_onetimeauth_verify(c, 16,c, 32,d - 32,x) !== 0) return -1;
  crypto_stream_xor(m,0,c,0,d,n,k);
  for (i = 0; i < 32; i++) m[i] = 0;
  return 0;
}

function set25519(r, a) {
  var i;
  for (i = 0; i < 16; i++) r[i] = a[i]|0;
}

function car25519(o) {
  var c;
  var i;
  for (i = 0; i < 16; i++) {
      o[i] += 65536;
      c = Math.floor(o[i] / 65536);
      o[(i+1)*(i<15?1:0)] += c - 1 + 37 * (c-1) * (i===15?1:0);
      o[i] -= (c * 65536);
  }
}

function sel25519(p, q, b) {
  var t, c = ~(b-1);
  for (var i = 0; i < 16; i++) {
    t = c & (p[i] ^ q[i]);
    p[i] ^= t;
    q[i] ^= t;
  }
}

function pack25519(o, n) {
  var i, j, b;
  var m = gf(), t = gf();
  for (i = 0; i < 16; i++) t[i] = n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  for (j = 0; j < 2; j++) {
    m[0] = t[0] - 0xffed;
    for (i = 1; i < 15; i++) {
      m[i] = t[i] - 0xffff - ((m[i-1]>>16) & 1);
      m[i-1] &= 0xffff;
    }
    m[15] = t[15] - 0x7fff - ((m[14]>>16) & 1);
    b = (m[15]>>16) & 1;
    m[14] &= 0xffff;
    sel25519(t, m, 1-b);
  }
  for (i = 0; i < 16; i++) {
    o[2*i] = t[i] & 0xff;
    o[2*i+1] = t[i]>>8;
  }
}

function neq25519(a, b) {
  var c = new Uint8Array(32), d = new Uint8Array(32);
  pack25519(c, a);
  pack25519(d, b);
  return crypto_verify_32(c, 0, d, 0);
}

function par25519(a) {
  var d = new Uint8Array(32);
  pack25519(d, a);
  return d[0] & 1;
}

function unpack25519(o, n) {
  var i;
  for (i = 0; i < 16; i++) o[i] = n[2*i] + (n[2*i+1] << 8);
  o[15] &= 0x7fff;
}

function A(o, a, b) {
  var i;
  for (i = 0; i < 16; i++) o[i] = (a[i] + b[i])|0;
}

function Z(o, a, b) {
  var i;
  for (i = 0; i < 16; i++) o[i] = (a[i] - b[i])|0;
}

function M(o, a, b) {
  var i, j, t = new Float64Array(31);
  for (i = 0; i < 31; i++) t[i] = 0;
  for (i = 0; i < 16; i++) {
    for (j = 0; j < 16; j++) {
      t[i+j] += a[i] * b[j];
    }
  }
  for (i = 0; i < 15; i++) {
    t[i] += 38 * t[i+16];
  }
  for (i = 0; i < 16; i++) o[i] = t[i];
  car25519(o);
  car25519(o);
}

function S(o, a) {
  M(o, a, a);
}

function inv25519(o, i) {
  var c = gf();
  var a;
  for (a = 0; a < 16; a++) c[a] = i[a];
  for (a = 253; a >= 0; a--) {
    S(c, c);
    if(a !== 2 && a !== 4) M(c, c, i);
  }
  for (a = 0; a < 16; a++) o[a] = c[a];
}

function pow2523(o, i) {
  var c = gf();
  var a;
  for (a = 0; a < 16; a++) c[a] = i[a];
  for (a = 250; a >= 0; a--) {
      S(c, c);
      if(a !== 1) M(c, c, i);
  }
  for (a = 0; a < 16; a++) o[a] = c[a];
}

function crypto_scalarmult(q, n, p) {
  var z = new Uint8Array(32);
  var x = new Float64Array(80), r, i;
  var a = gf(), b = gf(), c = gf(),
      d = gf(), e = gf(), f = gf();
  for (i = 0; i < 31; i++) z[i] = n[i];
  z[31]=(n[31]&127)|64;
  z[0]&=248;
  unpack25519(x,p);
  for (i = 0; i < 16; i++) {
    b[i]=x[i];
    d[i]=a[i]=c[i]=0;
  }
  a[0]=d[0]=1;
  for (i=254; i>=0; --i) {
    r=(z[i>>>3]>>>(i&7))&1;
    sel25519(a,b,r);
    sel25519(c,d,r);
    A(e,a,c);
    Z(a,a,c);
    A(c,b,d);
    Z(b,b,d);
    S(d,e);
    S(f,a);
    M(a,c,a);
    M(c,b,e);
    A(e,a,c);
    Z(a,a,c);
    S(b,a);
    Z(c,d,f);
    M(a,c,_121665);
    A(a,a,d);
    M(c,c,a);
    M(a,d,f);
    M(d,b,x);
    S(b,e);
    sel25519(a,b,r);
    sel25519(c,d,r);
  }
  for (i = 0; i < 16; i++) {
    x[i+16]=a[i];
    x[i+32]=c[i];
    x[i+48]=b[i];
    x[i+64]=d[i];
  }
  var x32 = x.subarray(32);
  var x16 = x.subarray(16);
  inv25519(x32,x32);
  M(x16,x16,x32);
  pack25519(q,x16);
  return 0;
}

function crypto_scalarmult_base(q, n) {
  return crypto_scalarmult(q, n, _9);
}

function crypto_box_keypair(y, x) {
  randombytes(x, 32);
  return crypto_scalarmult_base(y, x);
}

function crypto_box_beforenm(k, y, x) {
  var s = new Uint8Array(32);
  crypto_scalarmult(s, x, y);
  return crypto_core_hsalsa20(k, _0, s, sigma);
}

var crypto_box_afternm = crypto_secretbox;
var crypto_box_open_afternm = crypto_secretbox_open;

function crypto_box(c, m, d, n, y, x) {
  var k = new Uint8Array(32);
  crypto_box_beforenm(k, y, x);
  return crypto_box_afternm(c, m, d, n, k);
}

function crypto_box_open(m, c, d, n, y, x) {
  var k = new Uint8Array(32);
  crypto_box_beforenm(k, y, x);
  return crypto_box_open_afternm(m, c, d, n, k);
}

function add64() {
  var a = 0, b = 0, c = 0, d = 0, m16 = 65535, l, h, i;
  for (i = 0; i < arguments.length; i++) {
    l = arguments[i].lo;
    h = arguments[i].hi;
    a += (l & m16); b += (l >>> 16);
    c += (h & m16); d += (h >>> 16);
  }

  b += (a >>> 16);
  c += (b >>> 16);
  d += (c >>> 16);

  return new u64((c & m16) | (d << 16), (a & m16) | (b << 16));
}

function shr64(x, c) {
  return new u64((x.hi >>> c), (x.lo >>> c) | (x.hi << (32 - c)));
}

function xor64() {
  var l = 0, h = 0, i;
  for (i = 0; i < arguments.length; i++) {
    l ^= arguments[i].lo;
    h ^= arguments[i].hi;
  }
  return new u64(h, l);
}

function R(x, c) {
  var h, l, c1 = 32 - c;
  if (c < 32) {
    h = (x.hi >>> c) | (x.lo << c1);
    l = (x.lo >>> c) | (x.hi << c1);
  } else if (c < 64) {
    h = (x.lo >>> c) | (x.hi << c1);
    l = (x.hi >>> c) | (x.lo << c1);
  }
  return new u64(h, l);
}

function Ch(x, y, z) {
  var h = (x.hi & y.hi) ^ (~x.hi & z.hi),
      l = (x.lo & y.lo) ^ (~x.lo & z.lo);
  return new u64(h, l);
}

function Maj(x, y, z) {
  var h = (x.hi & y.hi) ^ (x.hi & z.hi) ^ (y.hi & z.hi),
      l = (x.lo & y.lo) ^ (x.lo & z.lo) ^ (y.lo & z.lo);
  return new u64(h, l);
}

function Sigma0(x) { return xor64(R(x,28), R(x,34), R(x,39)); }
function Sigma1(x) { return xor64(R(x,14), R(x,18), R(x,41)); }
function sigma0(x) { return xor64(R(x, 1), R(x, 8), shr64(x,7)); }
function sigma1(x) { return xor64(R(x,19), R(x,61), shr64(x,6)); }

var K = [
  new u64(0x428a2f98, 0xd728ae22), new u64(0x71374491, 0x23ef65cd),
  new u64(0xb5c0fbcf, 0xec4d3b2f), new u64(0xe9b5dba5, 0x8189dbbc),
  new u64(0x3956c25b, 0xf348b538), new u64(0x59f111f1, 0xb605d019),
  new u64(0x923f82a4, 0xaf194f9b), new u64(0xab1c5ed5, 0xda6d8118),
  new u64(0xd807aa98, 0xa3030242), new u64(0x12835b01, 0x45706fbe),
  new u64(0x243185be, 0x4ee4b28c), new u64(0x550c7dc3, 0xd5ffb4e2),
  new u64(0x72be5d74, 0xf27b896f), new u64(0x80deb1fe, 0x3b1696b1),
  new u64(0x9bdc06a7, 0x25c71235), new u64(0xc19bf174, 0xcf692694),
  new u64(0xe49b69c1, 0x9ef14ad2), new u64(0xefbe4786, 0x384f25e3),
  new u64(0x0fc19dc6, 0x8b8cd5b5), new u64(0x240ca1cc, 0x77ac9c65),
  new u64(0x2de92c6f, 0x592b0275), new u64(0x4a7484aa, 0x6ea6e483),
  new u64(0x5cb0a9dc, 0xbd41fbd4), new u64(0x76f988da, 0x831153b5),
  new u64(0x983e5152, 0xee66dfab), new u64(0xa831c66d, 0x2db43210),
  new u64(0xb00327c8, 0x98fb213f), new u64(0xbf597fc7, 0xbeef0ee4),
  new u64(0xc6e00bf3, 0x3da88fc2), new u64(0xd5a79147, 0x930aa725),
  new u64(0x06ca6351, 0xe003826f), new u64(0x14292967, 0x0a0e6e70),
  new u64(0x27b70a85, 0x46d22ffc), new u64(0x2e1b2138, 0x5c26c926),
  new u64(0x4d2c6dfc, 0x5ac42aed), new u64(0x53380d13, 0x9d95b3df),
  new u64(0x650a7354, 0x8baf63de), new u64(0x766a0abb, 0x3c77b2a8),
  new u64(0x81c2c92e, 0x47edaee6), new u64(0x92722c85, 0x1482353b),
  new u64(0xa2bfe8a1, 0x4cf10364), new u64(0xa81a664b, 0xbc423001),
  new u64(0xc24b8b70, 0xd0f89791), new u64(0xc76c51a3, 0x0654be30),
  new u64(0xd192e819, 0xd6ef5218), new u64(0xd6990624, 0x5565a910),
  new u64(0xf40e3585, 0x5771202a), new u64(0x106aa070, 0x32bbd1b8),
  new u64(0x19a4c116, 0xb8d2d0c8), new u64(0x1e376c08, 0x5141ab53),
  new u64(0x2748774c, 0xdf8eeb99), new u64(0x34b0bcb5, 0xe19b48a8),
  new u64(0x391c0cb3, 0xc5c95a63), new u64(0x4ed8aa4a, 0xe3418acb),
  new u64(0x5b9cca4f, 0x7763e373), new u64(0x682e6ff3, 0xd6b2b8a3),
  new u64(0x748f82ee, 0x5defb2fc), new u64(0x78a5636f, 0x43172f60),
  new u64(0x84c87814, 0xa1f0ab72), new u64(0x8cc70208, 0x1a6439ec),
  new u64(0x90befffa, 0x23631e28), new u64(0xa4506ceb, 0xde82bde9),
  new u64(0xbef9a3f7, 0xb2c67915), new u64(0xc67178f2, 0xe372532b),
  new u64(0xca273ece, 0xea26619c), new u64(0xd186b8c7, 0x21c0c207),
  new u64(0xeada7dd6, 0xcde0eb1e), new u64(0xf57d4f7f, 0xee6ed178),
  new u64(0x06f067aa, 0x72176fba), new u64(0x0a637dc5, 0xa2c898a6),
  new u64(0x113f9804, 0xbef90dae), new u64(0x1b710b35, 0x131c471b),
  new u64(0x28db77f5, 0x23047d84), new u64(0x32caab7b, 0x40c72493),
  new u64(0x3c9ebe0a, 0x15c9bebc), new u64(0x431d67c4, 0x9c100d4c),
  new u64(0x4cc5d4be, 0xcb3e42b6), new u64(0x597f299c, 0xfc657e2a),
  new u64(0x5fcb6fab, 0x3ad6faec), new u64(0x6c44198c, 0x4a475817)
];

function crypto_hashblocks(x, m, n) {
  var z = [], b = [], a = [], w = [], t, i, j;

  for (i = 0; i < 8; i++) z[i] = a[i] = dl64(x, 8*i);

  var pos = 0;
  while (n >= 128) {
    for (i = 0; i < 16; i++) w[i] = dl64(m, 8*i+pos);
    for (i = 0; i < 80; i++) {
      for (j = 0; j < 8; j++) b[j] = a[j];
      t = add64(a[7], Sigma1(a[4]), Ch(a[4], a[5], a[6]), K[i], w[i%16]);
      b[7] = add64(t, Sigma0(a[0]), Maj(a[0], a[1], a[2]));
      b[3] = add64(b[3], t);
      for (j = 0; j < 8; j++) a[(j+1)%8] = b[j];
      if (i%16 === 15) {
        for (j = 0; j < 16; j++) {
          w[j] = add64(w[j], w[(j+9)%16], sigma0(w[(j+1)%16]), sigma1(w[(j+14)%16]));
        }
      }
    }

    for (i = 0; i < 8; i++) {
      a[i] = add64(a[i], z[i]);
      z[i] = a[i];
    }

    pos += 128;
    n -= 128;
  }

  for (i = 0; i < 8; i++) ts64(x, 8*i, z[i]);
  return n;
}

var iv = new Uint8Array([
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
  0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
  0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
  0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
  0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
]);

function crypto_hash(out, m, n) {
  var h = new Uint8Array(64), x = new Uint8Array(256);
  var i, b = n;

  for (i = 0; i < 64; i++) h[i] = iv[i];

  crypto_hashblocks(h, m, n);
  n %= 128;

  for (i = 0; i < 256; i++) x[i] = 0;
  for (i = 0; i < n; i++) x[i] = m[b-n+i];
  x[n] = 128;

  n = 256-128*(n<112?1:0);
  x[n-9] = 0;
  ts64(x, n-8, new u64((b / 0x20000000) | 0, b << 3));
  crypto_hashblocks(h, x, n);

  for (i = 0; i < 64; i++) out[i] = h[i];

  return 0;
}

function add(p, q) {
  var a = gf(), b = gf(), c = gf(),
      d = gf(), e = gf(), f = gf(),
      g = gf(), h = gf(), t = gf();

  Z(a, p[1], p[0]);
  Z(t, q[1], q[0]);
  M(a, a, t);
  A(b, p[0], p[1]);
  A(t, q[0], q[1]);
  M(b, b, t);
  M(c, p[3], q[3]);
  M(c, c, D2);
  M(d, p[2], q[2]);
  A(d, d, d);
  Z(e, b, a);
  Z(f, d, c);
  A(g, d, c);
  A(h, b, a);

  M(p[0], e, f);
  M(p[1], h, g);
  M(p[2], g, f);
  M(p[3], e, h);
}

function cswap(p, q, b) {
  var i;
  for (i = 0; i < 4; i++) {
    sel25519(p[i], q[i], b);
  }
}

function pack(r, p) {
  var tx = gf(), ty = gf(), zi = gf();
  inv25519(zi, p[2]);
  M(tx, p[0], zi);
  M(ty, p[1], zi);
  pack25519(r, ty);
  r[31] ^= par25519(tx) << 7;
}

function scalarmult(p, q, s) {
  var b, i;
  set25519(p[0], gf0);
  set25519(p[1], gf1);
  set25519(p[2], gf1);
  set25519(p[3], gf0);
  for (i = 255; i >= 0; --i) {
    b = (s[(i/8)|0] >> (i&7)) & 1;
    cswap(p, q, b);
    add(q, p);
    add(p, p);
    cswap(p, q, b);
  }
}

function scalarbase(p, s) {
  var q = [gf(), gf(), gf(), gf()];
  set25519(q[0], X);
  set25519(q[1], Y);
  set25519(q[2], gf1);
  M(q[3], X, Y);
  scalarmult(p, q, s);
}

function crypto_sign_keypair(pk, sk, seeded) {
  var d = new Uint8Array(64);
  var p = [gf(), gf(), gf(), gf()];
  var i;

  if (!seeded) randombytes(sk, 32);
  crypto_hash(d, sk, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  scalarbase(p, d);
  pack(pk, p);

  for (i = 0; i < 32; i++) sk[i+32] = pk[i];
  return 0;
}

var L = new Float64Array([0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]);

function modL(r, x) {
  var carry, i, j, k;
  for (i = 63; i >= 32; --i) {
    carry = 0;
    for (j = i - 32, k = i - 12; j < k; ++j) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)];
      carry = Math.floor((x[j] + 128) / 256);
      x[j] -= carry * 256;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  for (j = 0; j < 32; j++) {
    x[j] += carry - (x[31] >> 4) * L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  for (j = 0; j < 32; j++) x[j] -= carry * L[j];
  for (i = 0; i < 32; i++) {
    x[i+1] += x[i] >> 8;
    r[i] = x[i] & 255;
  }
}

function reduce(r) {
  var x = new Float64Array(64), i;
  for (i = 0; i < 64; i++) x[i] = r[i];
  for (i = 0; i < 64; i++) r[i] = 0;
  modL(r, x);
}

// Note: difference from C - smlen returned, not passed as argument.
function crypto_sign(sm, m, n, sk) {
  var d = new Uint8Array(64), h = new Uint8Array(64), r = new Uint8Array(64);
  var i, j, x = new Float64Array(64);
  var p = [gf(), gf(), gf(), gf()];

  crypto_hash(d, sk, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  var smlen = n + 64;
  for (i = 0; i < n; i++) sm[64 + i] = m[i];
  for (i = 0; i < 32; i++) sm[32 + i] = d[32 + i];

  crypto_hash(r, sm.subarray(32), n+32);
  reduce(r);
  scalarbase(p, r);
  pack(sm, p);

  for (i = 32; i < 64; i++) sm[i] = sk[i];
  crypto_hash(h, sm, n + 64);
  reduce(h);

  for (i = 0; i < 64; i++) x[i] = 0;
  for (i = 0; i < 32; i++) x[i] = r[i];
  for (i = 0; i < 32; i++) {
    for (j = 0; j < 32; j++) {
      x[i+j] += h[i] * d[j];
    }
  }

  modL(sm.subarray(32), x);
  return smlen;
}

function unpackneg(r, p) {
  var t = gf(), chk = gf(), num = gf(),
      den = gf(), den2 = gf(), den4 = gf(),
      den6 = gf();

  set25519(r[2], gf1);
  unpack25519(r[1], p);
  S(num, r[1]);
  M(den, num, D);
  Z(num, num, r[2]);
  A(den, r[2], den);

  S(den2, den);
  S(den4, den2);
  M(den6, den4, den2);
  M(t, den6, num);
  M(t, t, den);

  pow2523(t, t);
  M(t, t, num);
  M(t, t, den);
  M(t, t, den);
  M(r[0], t, den);

  S(chk, r[0]);
  M(chk, chk, den);
  if (neq25519(chk, num)) M(r[0], r[0], I);

  S(chk, r[0]);
  M(chk, chk, den);
  if (neq25519(chk, num)) return -1;

  if (par25519(r[0]) === (p[31]>>7)) Z(r[0], gf0, r[0]);

  M(r[3], r[0], r[1]);
  return 0;
}

function crypto_sign_open(m, sm, n, pk) {
  var i;
  var t = new Uint8Array(32), h = new Uint8Array(64);
  var p = [gf(), gf(), gf(), gf()],
      q = [gf(), gf(), gf(), gf()];

  if (n < 64) return -1;

  if (unpackneg(q, pk)) return -1;

  for (i = 0; i < n; i++) m[i] = sm[i];
  for (i = 0; i < 32; i++) m[i+32] = pk[i];
  crypto_hash(h, m, n);
  reduce(h);
  scalarmult(p, q, h);

  scalarbase(q, sm.subarray(32));
  add(p, q);
  pack(t, p);

  n -= 64;
  if (crypto_verify_32(sm, 0, t, 0)) {
    for (i = 0; i < n; i++) m[i] = 0;
    return -1;
  }

  for (i = 0; i < n; i++) m[i] = sm[i + 64];
  return n;
}

var crypto_secretbox_KEYBYTES = 32,
    crypto_secretbox_NONCEBYTES = 24,
    crypto_secretbox_ZEROBYTES = 32,
    crypto_secretbox_BOXZEROBYTES = 16,
    crypto_scalarmult_BYTES = 32,
    crypto_scalarmult_SCALARBYTES = 32,
    crypto_box_PUBLICKEYBYTES = 32,
    crypto_box_SECRETKEYBYTES = 32,
    crypto_box_BEFORENMBYTES = 32,
    crypto_box_NONCEBYTES = crypto_secretbox_NONCEBYTES,
    crypto_box_ZEROBYTES = crypto_secretbox_ZEROBYTES,
    crypto_box_BOXZEROBYTES = crypto_secretbox_BOXZEROBYTES,
    crypto_sign_BYTES = 64,
    crypto_sign_PUBLICKEYBYTES = 32,
    crypto_sign_SECRETKEYBYTES = 64,
    crypto_sign_SEEDBYTES = 32,
    crypto_hash_BYTES = 64;

nacl.lowlevel = {
  crypto_core_hsalsa20: crypto_core_hsalsa20,
  crypto_stream_xor: crypto_stream_xor,
  crypto_stream: crypto_stream,
  crypto_stream_salsa20_xor: crypto_stream_salsa20_xor,
  crypto_stream_salsa20: crypto_stream_salsa20,
  crypto_onetimeauth: crypto_onetimeauth,
  crypto_onetimeauth_verify: crypto_onetimeauth_verify,
  crypto_verify_16: crypto_verify_16,
  crypto_verify_32: crypto_verify_32,
  crypto_secretbox: crypto_secretbox,
  crypto_secretbox_open: crypto_secretbox_open,
  crypto_scalarmult: crypto_scalarmult,
  crypto_scalarmult_base: crypto_scalarmult_base,
  crypto_box_beforenm: crypto_box_beforenm,
  crypto_box_afternm: crypto_box_afternm,
  crypto_box: crypto_box,
  crypto_box_open: crypto_box_open,
  crypto_box_keypair: crypto_box_keypair,
  crypto_hash: crypto_hash,
  crypto_sign: crypto_sign,
  crypto_sign_keypair: crypto_sign_keypair,
  crypto_sign_open: crypto_sign_open,

  crypto_secretbox_KEYBYTES: crypto_secretbox_KEYBYTES,
  crypto_secretbox_NONCEBYTES: crypto_secretbox_NONCEBYTES,
  crypto_secretbox_ZEROBYTES: crypto_secretbox_ZEROBYTES,
  crypto_secretbox_BOXZEROBYTES: crypto_secretbox_BOXZEROBYTES,
  crypto_scalarmult_BYTES: crypto_scalarmult_BYTES,
  crypto_scalarmult_SCALARBYTES: crypto_scalarmult_SCALARBYTES,
  crypto_box_PUBLICKEYBYTES: crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES: crypto_box_SECRETKEYBYTES,
  crypto_box_BEFORENMBYTES: crypto_box_BEFORENMBYTES,
  crypto_box_NONCEBYTES: crypto_box_NONCEBYTES,
  crypto_box_ZEROBYTES: crypto_box_ZEROBYTES,
  crypto_box_BOXZEROBYTES: crypto_box_BOXZEROBYTES,
  crypto_sign_BYTES: crypto_sign_BYTES,
  crypto_sign_PUBLICKEYBYTES: crypto_sign_PUBLICKEYBYTES,
  crypto_sign_SECRETKEYBYTES: crypto_sign_SECRETKEYBYTES,
  crypto_sign_SEEDBYTES: crypto_sign_SEEDBYTES,
  crypto_hash_BYTES: crypto_hash_BYTES,

  gf: gf,
  D: D,
  L: L,
  pack25519: pack25519,
  unpack25519: unpack25519,
  M: M,
  A: A,
  S: S,
  Z: Z,
  pow2523: pow2523,
  add: add,
  set25519: set25519,
  modL: modL,
  scalarmult: scalarmult,
  scalarbase: scalarbase,
};

/* High-level API */

function checkLengths(k, n) {
  if (k.length !== crypto_secretbox_KEYBYTES) throw new Error('bad key size');
  if (n.length !== crypto_secretbox_NONCEBYTES) throw new Error('bad nonce size');
}

function checkBoxLengths(pk, sk) {
  if (pk.length !== crypto_box_PUBLICKEYBYTES) throw new Error('bad public key size');
  if (sk.length !== crypto_box_SECRETKEYBYTES) throw new Error('bad secret key size');
}

function checkArrayTypes() {
  for (var i = 0; i < arguments.length; i++) {
    if (!(arguments[i] instanceof Uint8Array))
      throw new TypeError('unexpected type, use Uint8Array');
  }
}

function cleanup(arr) {
  for (var i = 0; i < arr.length; i++) arr[i] = 0;
}

nacl.randomBytes = function(n) {
  var b = new Uint8Array(n);
  randombytes(b, n);
  return b;
};

nacl.secretbox = function(msg, nonce, key) {
  checkArrayTypes(msg, nonce, key);
  checkLengths(key, nonce);
  var m = new Uint8Array(crypto_secretbox_ZEROBYTES + msg.length);
  var c = new Uint8Array(m.length);
  for (var i = 0; i < msg.length; i++) m[i+crypto_secretbox_ZEROBYTES] = msg[i];
  crypto_secretbox(c, m, m.length, nonce, key);
  return c.subarray(crypto_secretbox_BOXZEROBYTES);
};

nacl.secretbox.open = function(box, nonce, key) {
  checkArrayTypes(box, nonce, key);
  checkLengths(key, nonce);
  var c = new Uint8Array(crypto_secretbox_BOXZEROBYTES + box.length);
  var m = new Uint8Array(c.length);
  for (var i = 0; i < box.length; i++) c[i+crypto_secretbox_BOXZEROBYTES] = box[i];
  if (c.length < 32) return null;
  if (crypto_secretbox_open(m, c, c.length, nonce, key) !== 0) return null;
  return m.subarray(crypto_secretbox_ZEROBYTES);
};

nacl.secretbox.keyLength = crypto_secretbox_KEYBYTES;
nacl.secretbox.nonceLength = crypto_secretbox_NONCEBYTES;
nacl.secretbox.overheadLength = crypto_secretbox_BOXZEROBYTES;

nacl.scalarMult = function(n, p) {
  checkArrayTypes(n, p);
  if (n.length !== crypto_scalarmult_SCALARBYTES) throw new Error('bad n size');
  if (p.length !== crypto_scalarmult_BYTES) throw new Error('bad p size');
  var q = new Uint8Array(crypto_scalarmult_BYTES);
  crypto_scalarmult(q, n, p);
  return q;
};

nacl.scalarMult.base = function(n) {
  checkArrayTypes(n);
  if (n.length !== crypto_scalarmult_SCALARBYTES) throw new Error('bad n size');
  var q = new Uint8Array(crypto_scalarmult_BYTES);
  crypto_scalarmult_base(q, n);
  return q;
};

nacl.scalarMult.scalarLength = crypto_scalarmult_SCALARBYTES;
nacl.scalarMult.groupElementLength = crypto_scalarmult_BYTES;

nacl.box = function(msg, nonce, publicKey, secretKey) {
  var k = nacl.box.before(publicKey, secretKey);
  return nacl.secretbox(msg, nonce, k);
};

nacl.box.before = function(publicKey, secretKey) {
  checkArrayTypes(publicKey, secretKey);
  checkBoxLengths(publicKey, secretKey);
  var k = new Uint8Array(crypto_box_BEFORENMBYTES);
  crypto_box_beforenm(k, publicKey, secretKey);
  return k;
};

nacl.box.after = nacl.secretbox;

nacl.box.open = function(msg, nonce, publicKey, secretKey) {
  var k = nacl.box.before(publicKey, secretKey);
  return nacl.secretbox.open(msg, nonce, k);
};

nacl.box.open.after = nacl.secretbox.open;

nacl.box.keyPair = function() {
  var pk = new Uint8Array(crypto_box_PUBLICKEYBYTES);
  var sk = new Uint8Array(crypto_box_SECRETKEYBYTES);
  crypto_box_keypair(pk, sk);
  return {publicKey: pk, secretKey: sk};
};

nacl.box.keyPair.fromSecretKey = function(secretKey) {
  checkArrayTypes(secretKey);
  if (secretKey.length !== crypto_box_SECRETKEYBYTES)
    throw new Error('bad secret key size');
  var pk = new Uint8Array(crypto_box_PUBLICKEYBYTES);
  crypto_scalarmult_base(pk, secretKey);
  return {publicKey: pk, secretKey: new Uint8Array(secretKey)};
};

nacl.box.publicKeyLength = crypto_box_PUBLICKEYBYTES;
nacl.box.secretKeyLength = crypto_box_SECRETKEYBYTES;
nacl.box.sharedKeyLength = crypto_box_BEFORENMBYTES;
nacl.box.nonceLength = crypto_box_NONCEBYTES;
nacl.box.overheadLength = nacl.secretbox.overheadLength;

nacl.sign = function(msg, secretKey) {
  checkArrayTypes(msg, secretKey);
  if (secretKey.length !== crypto_sign_SECRETKEYBYTES)
    throw new Error('bad secret key size');
  var signedMsg = new Uint8Array(crypto_sign_BYTES+msg.length);
  crypto_sign(signedMsg, msg, msg.length, secretKey);
  return signedMsg;
};

nacl.sign.open = function(signedMsg, publicKey) {
  checkArrayTypes(signedMsg, publicKey);
  if (publicKey.length !== crypto_sign_PUBLICKEYBYTES)
    throw new Error('bad public key size');
  var tmp = new Uint8Array(signedMsg.length);
  var mlen = crypto_sign_open(tmp, signedMsg, signedMsg.length, publicKey);
  if (mlen < 0) return null;
  var m = new Uint8Array(mlen);
  for (var i = 0; i < m.length; i++) m[i] = tmp[i];
  return m;
};

nacl.sign.detached = function(msg, secretKey) {
  var signedMsg = nacl.sign(msg, secretKey);
  var sig = new Uint8Array(crypto_sign_BYTES);
  for (var i = 0; i < sig.length; i++) sig[i] = signedMsg[i];
  return sig;
};

nacl.sign.detached.verify = function(msg, sig, publicKey) {
  checkArrayTypes(msg, sig, publicKey);
  if (sig.length !== crypto_sign_BYTES)
    throw new Error('bad signature size');
  if (publicKey.length !== crypto_sign_PUBLICKEYBYTES)
    throw new Error('bad public key size');
  var sm = new Uint8Array(crypto_sign_BYTES + msg.length);
  var m = new Uint8Array(crypto_sign_BYTES + msg.length);
  var i;
  for (i = 0; i < crypto_sign_BYTES; i++) sm[i] = sig[i];
  for (i = 0; i < msg.length; i++) sm[i+crypto_sign_BYTES] = msg[i];
  return (crypto_sign_open(m, sm, sm.length, publicKey) >= 0);
};

nacl.sign.keyPair = function() {
  var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
  var sk = new Uint8Array(crypto_sign_SECRETKEYBYTES);
  crypto_sign_keypair(pk, sk);
  return {publicKey: pk, secretKey: sk};
};

nacl.sign.keyPair.fromSecretKey = function(secretKey) {
  checkArrayTypes(secretKey);
  if (secretKey.length !== crypto_sign_SECRETKEYBYTES)
    throw new Error('bad secret key size');
  var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
  for (var i = 0; i < pk.length; i++) pk[i] = secretKey[32+i];
  return {publicKey: pk, secretKey: new Uint8Array(secretKey)};
};

nacl.sign.keyPair.fromSeed = function(seed) {
  checkArrayTypes(seed);
  if (seed.length !== crypto_sign_SEEDBYTES)
    throw new Error('bad seed size');
  var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
  var sk = new Uint8Array(crypto_sign_SECRETKEYBYTES);
  for (var i = 0; i < 32; i++) sk[i] = seed[i];
  crypto_sign_keypair(pk, sk, true);
  return {publicKey: pk, secretKey: sk};
};

nacl.sign.publicKeyLength = crypto_sign_PUBLICKEYBYTES;
nacl.sign.secretKeyLength = crypto_sign_SECRETKEYBYTES;
nacl.sign.seedLength = crypto_sign_SEEDBYTES;
nacl.sign.signatureLength = crypto_sign_BYTES;

nacl.hash = function(msg) {
  checkArrayTypes(msg);
  var h = new Uint8Array(crypto_hash_BYTES);
  crypto_hash(h, msg, msg.length);
  return h;
};

nacl.hash.hashLength = crypto_hash_BYTES;

nacl.verify = function(x, y) {
  checkArrayTypes(x, y);
  // Zero length arguments are considered not equal.
  if (x.length === 0 || y.length === 0) return false;
  if (x.length !== y.length) return false;
  return (vn(x, 0, y, 0, x.length) === 0) ? true : false;
};

nacl.setPRNG = function(fn) {
  randombytes = fn;
};

(function() {
  // Initialize PRNG if environment provides CSPRNG.
  // If not, methods calling randombytes will throw.
  var crypto = typeof self !== 'undefined' ? (self.crypto || self.msCrypto) : null;
  if (crypto && crypto.getRandomValues) {
    // Browsers.
    var QUOTA = 65536;
    nacl.setPRNG(function(x, n) {
      var i, v = new Uint8Array(n);
      for (i = 0; i < n; i += QUOTA) {
        crypto.getRandomValues(v.subarray(i, i + Math.min(n - i, QUOTA)));
      }
      for (i = 0; i < n; i++) x[i] = v[i];
      cleanup(v);
    });
  } else if (typeof require !== 'undefined') {
    // Node.js.
    crypto = require('crypto');
    if (crypto && crypto.randomBytes) {
      nacl.setPRNG(function(x, n) {
        var i, v = crypto.randomBytes(n);
        for (i = 0; i < n; i++) x[i] = v[i];
        cleanup(v);
      });
    }
  }
})();

})(typeof module !== 'undefined' && module.exports ? module.exports : (self.nacl = self.nacl || {}));


// Cloudflare Worker —— 成员自助接入。
// 主通道：手机 + 短信验证码登录网易云 → 拿 MUSIC_U。
// 手动登记：成员直接粘贴浏览器里的 MUSIC_U（短信收不到 / 登录失败时用）。
// 两通道都：解析分享链接拿 song id → 用 KV 维护主号池 → 重算分片 → 覆盖写 GitHub Secrets(NB_POOL_1..5)。
// 需要的 CF 环境变量/绑定：
//   GH_TOKEN   有 repo 权限的 GitHub PAT（写 secret 用，仅服务端，不落前端）
//   GH_OWNER   仓库 owner（如 xm921018）
//   GH_REPO    仓库名（如 cron-relay）
//   GROUP_PASS 管理暗号（2026-10-20 起登记接口不再校验，仅供 /api/resync、/api/report_dead 两个隐藏管理接口）
//   POOL_LIMIT_G1 一群登记上限（默认 500，2026-10-21 由 200 上调）。二群已独立为 dingzhi 系统（自带 500 上限），
//                 主 worker 不再使用 GROUP_PASS2 / POOL_LIMIT_G2（cfg 中保留仅为兼容 stats 字段）
//   POOL       KV namespace 绑定（维护主号池，cookie 不落 GitHub 仓库文件）
// 注意：cookie 只在 KV 与 GitHub Secrets（加密）中存在，仓库文件无明文。


const BASE = 'https://music.163.com';
const NONCE = '0CoJUm6Qyw8W8jud';
const SECRET = 'TA3YiYCfY2dDJQgg';
const VI = '0102030405060708';
const ENCSEC = '84ca47bca10bad09a6b04c5c927ef077d9b9f1e37098aa3eac6ea70eb59df0aa28b691b7e75e4f1f9831754919ea784c8f74fbfadf2898b0be17849fd656060162857830e241aba44991601f137624094c114ea8d17bce815b0cd4e5b8e2fbaba978c6d1d14dc3d1faf852bdd28818031ccdaaa13a6018e1024e2aae98844210';

const UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148';

// ---- base64 ----
const b64enc = (u8) => btoa(String.fromCharCode(...new Uint8Array(u8)));
const b64dec = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const utf8 = (s) => new TextEncoder().encode(s);

// ---- AES-CBC (WebCrypto) ----
// 2026-11-12 修复：旧版在 WebCrypto 之前手动补 PKCS#7 位，而 crypto.subtle 的
// AES-CBC 本身还会再加一层 PKCS#7 —— 双重 padding，网易按标准解密后 JSON 尾部
// 带垃圾字节，JSON.parse 必失败（tmp/_test_weapi_padding_1112.mjs 实测：
// 旧版 FAIL / 修正版 OK）。WebCrypto 自动补位即标准 PKCS#7，手动补位必须去掉。
// 此函数此前无任何调用者（weapi 2026-11-12 才第一次被用上），不影响存量功能。
async function aesCbc(dataU8, keyStr) {
  const key = await crypto.subtle.importKey('raw', utf8(keyStr), { name: 'AES-CBC' }, false, ['encrypt']);
  const ct = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: utf8(VI) }, key, dataU8);
  return new Uint8Array(ct);
}
// weapi 标准实现：
//   json → AES(NONCE) → base64 → AES(随机16字符key) → base64 = params
//   encSecKey = RSA(随机key 反转后按 ASCII 转 hex, e=010001) 转 hex 补零到 256 位
// 2026-11-12：aesCbc 双重 padding 修复后才真正可用；本函数在 worker 内首次
// 被扫码链（ncNewKey/ncPollOnce）调用。加密格式已用 tmp/_test_weapi_padding_1112.mjs
// 按网易端标准解密路径验证：JSON 完整还原、无垃圾尾部。
const RSA_MODULUS = '00e0b509f6259df8642dbc35662901477df22677ec152b5ff68ace615bb7b725152b3ab17a876aea8a5aa76d2e417629ec4ee341f56135fccf695280104e0312ecbda92557c93870114af6c9d05c4f7f0c3685b7a46bee255932575cce10b424d813cfe4875d3e82047b97ddef52741d546b8e289dc6935b3ece0462db0a22b8e7';
function modPow(b, e, m) { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; }
async function weapi(data) {
  const chars = '0123456789abcdef';
  const rnd = [...crypto.getRandomValues(new Uint8Array(16))].map(x => chars[x % 16]).join('');
  let p = await aesCbc(utf8(JSON.stringify(data)), NONCE);
  p = b64enc(p);
  p = await aesCbc(utf8(p), rnd);
  const rev = rnd.split('').reverse().join('');
  const hexOfAscii = [...rev].map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
  const encSecKey = modPow(BigInt('0x' + hexOfAscii), 0x10001n, BigInt('0x' + RSA_MODULUS)).toString(16).padStart(256, '0');
  return { params: b64enc(p), encSecKey };
}

// ===== 2026-11-05 新增：650 进度「实时复核」（只读 eapi 查询） =====
// 为什么需要：run.py 写的每日快照有可能采在网易结算之前（同一个号 07:20 快照 0%、11:30 再查已 100%），
// 控制台据此把正常号标成「有播放·650为0·卡住」。出数据前对这些号直接实时查一次真值，
// 结果挂在 snap.cur[pool][uid].lr / .lp 上，前端不再误报（不改原来的 rate，避免波及其它列/统计）。
// eapi 的 params 只由 path + body 决定（AES-128-ECB 固定 key+salt，没有随机数与时间戳），
// 所以空 body 那一份是常量，直接写死 —— 免得在 worker 里实现 WebCrypto 不支持的 AES-ECB。
const VIP650_URL = 'https://music.163.com/eapi/nmusician/workbench/special/right/vip/info';
const VIP650_PARAMS = 'C7C7706BEC685AFFBD66B336DEB116EE5E795D77ED2A710732DF882A7E766B801A6AB048A7A0219906A7128F3DC557285BBA0E0E56212455590495470F897141AB0BC662DE5F4FCE316572A95D9C24917DA4CC52FAD61584010C99D200D3941286C8B02E57F2AED06305C4F78F8404AB';
async function live650(ck) {
  const ctl = (typeof AbortSignal !== 'undefined' && AbortSignal.timeout) ? AbortSignal.timeout(8000) : undefined;
  const r = await fetch(VIP650_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      // 固定桌面 Chrome UA（与 run.py 的 Client 一致；worker 全局那个 UA 是 iPhone 的，别混用）
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Referer': 'https://music.163.com',
      // 只给 MUSIC_U 会被回 301（2026-11-05 实测）；补 os/appver 后全部 200，不需要 deviceId
      'Cookie': String(ck) + '; os=pc; appver=2.10.11.200601',
    },
    body: 'params=' + VIP650_PARAMS,
    signal: ctl,
  });
  const d = await r.json();
  if (!d || d.code !== 200) return null;
  const dd = d.data || {};
  let rate = null;
  for (const k of ((dd.furtherTask || {}).children || [])) {
    if (k && k.missionCode === 'mission_code_recently_play_effect_count_v2' && k.progressRate != null) rate = Number(k.progressRate) || 0;
  }
  if (rate == null) return null;
  return { r: rate, p: dd.recentPlayCount30 == null ? null : (Number(dd.recentPlayCount30) || 0) };
}
// 批量复核：整批缓存 30 分钟（`l650b:<北京日期>` 单键），命中就不打网易。
// 只缓存成功结果 —— 失败（号被限流/接口超时）留 5 分钟哨兵，下次刷新再试。
// 2026-11-10 晚：从 KV 搬到 Cache API 之后发现一个更关键的问题 —— 原本「一个号一个键」，
//   40 个候选就是 40 次 caGet + 40 次 caPut，而免费版 Worker 单次 invocation 只有 50 个
//   subrequest（Cache API 读写和 fetch 一样计数）。首屏光这里就能把额度吃光，导致
//   /api/console/data 末尾写首屏缓存时直接抛 "Too many subrequests"，那份缓存从 11-09 起
//   就一次都没写进去过（控制台每次都要跑满 10 秒全量查询）。
//   改成整批单键后：读写各 1 次，subrequest 从最多 80 降到 2，功能与返回值结构完全不变。
//   唯一代价：并发刷新时读改写会互相覆盖几条结果（都是缓存，最多重查一次）。
async function live650Batch(list) {
  const out = {};
  const batchKey = 'l650b:' + beijingDate();
  let cur = {};
  try {
    const raw = await caGet(batchKey);
    if (raw) { const o = JSON.parse(raw); if (o && typeof o === 'object') cur = o; }
  } catch (e) { cur = {}; }
  const now = Date.now();
  const todo = [];
  list.forEach((c) => {
    const rec = cur[String(c.uid)];
    // 命中条件：有记录，且没过它自己的有效期 —— 成功结果 30 分钟（与原单键 TTL 1800 一致），
    // 空哨兵 5 分钟（与原 TTL 300 一致）。
    // 2026-11-10 晚修：原来只判「空哨兵」不判成功记录的年龄 —— 而整批回写每次都把 batchKey 的
    //   TTL 续到 30 分钟，只要这 40 个候选里有一个号持续查不通（每次刷新都会整批回写），
    //   cur 里其它号的成功记录就永远命中、永不过期 → 控制台「650 复核」那两列几天不刷新，
    //   而且完全静默（数字停在旧值，没有任何报错）。加年龄判定后每号最多 30 分钟必重查一次。
    const recAge = now - (Number(rec && rec.t) || 0);
    if (rec && recAge <= ((rec.r != null) ? 1800000 : 300000)) {
      out[c.uid] = { r: rec.r == null ? null : rec.r, p: rec.p == null ? null : rec.p };
      return;
    }
    todo.push(c);
  });
  if (!todo.length) return out;
  let cks = {};
  try {
    const rs = await d1All('SELECT pool,uid,ck FROM accounts WHERE uid IN (' + todo.map(() => '?').join(',') + ')',
                           todo.map(c => String(c.uid)));
    if (!rs) console.error('[console] 650 复核的 CK 补查失败，这批号本次按快照显示');
    for (const r of (rs || [])) {
      cks[(r.pool === 'dz' ? 'dz' : 'hz') + '|' + String(r.uid)] = r.ck || '';
    }
  } catch (e) { return out; }
  // 时间预算：最多等 5 秒就返回已经拿到的部分（out 由各 job 边跑边写）。
  // 控制台的 /api/console/data 是页面首屏请求，不能为了复核让首屏等十几秒；
  // 超时没回来的号本次就按快照显示，30 分钟后这轮的缓存过期再查。
  await Promise.race([
    Promise.all(todo.map(async (c) => {
    const ck = cks[c.pool + '|' + String(c.uid)];
    if (!ck) return;
    try {
      const v = await live650(ck);
      if (!v) {
        // 查不通（限流/超时/接口结构变化）：留 5 分钟空哨兵，别每次刷新都去撞
        cur[String(c.uid)] = { r: null, p: null, t: Date.now() };
        return;
      }
      out[c.uid] = v;
      cur[String(c.uid)] = { r: v.r == null ? null : v.r, p: v.p == null ? null : v.p, t: Date.now() };
    } catch (e) {}
    })),
    new Promise(res => setTimeout(res, 5000)),
  ]);
  // 整批回写一次（原来这里是最多 40 次 caPut）
  try { await caPut(batchKey, JSON.stringify(cur), 1800); } catch (e) {}
  return out;
}

// 校验一个 MUSIC_U 是否还活着（手动登记即时反馈）
// 策略：重试 2 次；若网易接口不可达（网络/非 JSON 响应）且 cookie 形状合法，降级放行（provisional），
// 交由次日 Actions 的 login_by_cookie 复验，失效号会被 /api/report_dead 自动清理。
async function validateCookie(musicU) {
  const ck = 'MUSIC_U=' + musicU;
  let lastDiag = '';
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      // 普通接口（非 weapi）：带 cookie 直接查账号，2026-10-10 实测返回 JSON
      const r = await fetch(`${BASE}/api/nuser/account/get`, {
        method: 'GET',
        headers: { 'User-Agent': UA, Referer: BASE + '/', 'Cookie': ck },
      });
      const txt = await r.text();
      let j = null;
      try { j = JSON.parse(txt); } catch (e) {}
      if (j && j.code === 200 && (j.profile || {}).userId) return { ok: true, uid: j.profile.userId };
      if (j) return { ok: false, msg: 'MUSIC_U 无效或已失效（code=' + j.code + '，请重新从浏览器复制）' };
      lastDiag = 'HTTP ' + r.status + '，响应非 JSON：' + txt.slice(0, 60);
    } catch (e) {
      lastDiag = '网络异常：' + ((e && e.message) || e);
    }
    if (attempt < 2) await new Promise(res => setTimeout(res, 800));
  }
  if (/^[0-9a-fA-F]{80,}$/.test(musicU)) {
    const hex = [...blake2b(utf8(musicU), 6)].map(b => b.toString(16).padStart(2, '0')).join('');
    return { ok: true, uid: Number('0x' + hex.slice(0, 12)) % 1e12, provisional: true, diag: lastDiag };
  }
  return { ok: false, msg: '校验失败：' + lastDiag + '；且 cookie 形状不对，请重新从浏览器复制 MUSIC_U' };
}

async function resolveSong(link) {
  // 容错：成员经常把 APP 分享的整段文字（带歌名/emoji/@）直接粘进来，先提取出里面的第一个 URL
  const picked = link.match(/https?:\/\/[^\s"'《》<>，,）)】]+/);
  let url = (picked ? picked[0] : link).trim();
  // 2026-11-09：域名白名单。原来对用户给的任意 URL 直接 fetch（含跟随重定向），
  // 买家可以把这里当成「我方出口 IP 的开放 GET 代理 / SSRF 跳板」，去打任意站点。
  // 只放行网易云自家分享域（music.163.com / y.music.163.com / 163cn.tv 短链）。
  const songHostOk = h => /(^|\.)(163\.com|163cn\.tv|163cn\.com)$/i.test(String(h || ''));
  const hostOf = u => { try { return new URL(u).hostname; } catch (e) { return ''; } };
  if (!/^https?:\/\//i.test(url) || !songHostOk(hostOf(url))) {
    return { ok: false, msg: '只支持网易云官方链接（music.163.com 或 163cn.tv 开头的）。请在网易云 APP 里打开那首歌 → 分享 → 复制链接' };
  }
  // 先在【原链接】上提取 id：网易云 APP 分享出来的单曲链接是 SPA 格式
  // music.163.com/#/song?id=xxx，井号后是 URL fragment，HTTP 请求不发送 fragment，
  // fetch 之后的 r.url 会把 id 一起丢掉，所以必须在 fetch 之前匹配
  // （网页版复制的 song?id= 格式、短链重定向后的 URL 同样兼容）
  let m = url.match(/[?&]id=(\d+)/);
  // 只收单曲：歌单/专辑/电台/节目/排行榜链接一律拒绝（防一个链接带出整张歌单）
  const COLLECT = /\/(playlist|album|radio|program|toplist|djradio|artist|mv)\b/i;
  if (COLLECT.test(url)) {
    return { ok: false, msg: '只收单曲链接：专辑 / 歌单 / 电台 / 排行榜 / MV 都不能登记。请在网易云 APP 里打开【那首歌】→ 分享 → 复制链接' };
  }
  let diag = '';
  try {
    const r = await fetch(url, { redirect: 'follow', headers: { 'User-Agent': UA } });
    // 短链跳转后仍必须是网易自家域名，否则说明这个「163cn.tv」指到了外面的站点
    if (!songHostOk(hostOf(r.url))) {
      return { ok: false, msg: '这个链接跳到了非网易云的站点，已拒绝。请在 APP 里重新分享那首歌的链接' };
    }
    url = r.url;
  } catch (e) {
    diag = 'fetch 异常：' + ((e && e.message) || e);
  }
  // 2026-11-12：短链解析兜底。此前 fetch 抛错被静默吞掉、或 163cn.tv 对数据中心请求
  // 不回 302 时，url 停在短链上 → 误报「链接里没找到歌曲 id」（bkNIU2s2 实测，本地 302 正常）。
  // 补：重试一次 follow + manual 模式直读 Location 头，报错时附带诊断信息。
  if (!m) m = url.match(/[?&]id=(\d+)/);
  if (!m) {
    await new Promise(res => setTimeout(res, 800));
    try {
      const r = await fetch(url, { redirect: 'follow', headers: { 'User-Agent': UA } });
      if (!songHostOk(hostOf(r.url))) {
        return { ok: false, msg: '这个链接跳到了非网易云的站点，已拒绝。请在 APP 里重新分享那首歌的链接' };
      }
      url = r.url;
    } catch (e) {
      diag = diag || ('重试 fetch 异常：' + ((e && e.message) || e));
    }
  }
  if (!m) {
    try {
      const r2 = await fetch(url, { redirect: 'manual', headers: { 'User-Agent': UA } });
      const loc = r2.headers.get('location') || '';
      if (loc && songHostOk(hostOf(loc))) {
        url = loc;
        m = loc.match(/[?&]id=(\d+)/);
        if (!m) diag = 'Location 无 id：' + loc.slice(0, 80);
      } else if (loc) {
        return { ok: false, msg: '这个链接跳到了非网易云的站点，已拒绝。请在 APP 里重新分享那首歌的链接' };
      } else {
        diag = diag || ('未返回 Location，HTTP ' + r2.status);
      }
    } catch (e) {
      diag = diag || ('manual fetch 异常：' + ((e && e.message) || e));
    }
  }
  if (COLLECT.test(url)) {
    return { ok: false, msg: '只收单曲链接：专辑 / 歌单 / 电台 / 排行榜 / MV 都不能登记。请在网易云 APP 里打开【那首歌】→ 分享 → 复制链接' };
  }
  // 原链接没带 id（如 163cn.tv 短链）时，用跟随重定向后的 r.url 兜底匹配一次
  if (!m) m = url.match(/[?&]id=(\d+)/);
  if (!m) return { ok: false, msg: '链接里没找到歌曲 id：识别到 ' + url.slice(0, 80) + (diag ? '（诊断：' + diag + '）' : '') + '。请在网易云 APP 里点「分享→复制链接」，把 http 开头的完整链接粘过来' };
  // 双保险：调网易歌曲详情接口确认这个 id 确实是一首歌（防歌单/电台 id 伪装混入）
  try {
    const r = await fetch(`${BASE}/api/song/detail?id=${m[1]}&ids=%5B${m[1]}%5D`, { headers: { 'User-Agent': UA, Referer: BASE + '/' } });
    const j = await r.json();
    if (!j || !Array.isArray(j.songs) || !j.songs.length) {
      return { ok: false, msg: '这个链接不是单曲（可能是歌单/电台/专辑 id）。请分享【单曲】：APP 里播放那首歌 → 分享 → 复制链接' };
    }
  } catch (e) {
    // 详情接口偶发异常时放行（歌单类 URL 已在上面被路径检查拦截）
  }
  return { ok: true, song: Number(m[1]) };
}

// ---- GitHub Secrets（sealed box） ----
// GH_TOKEN / GROUP_PASS 存于 KV（加密、不落仓库、不暴露给前端），运行时从 POOL 读取。
// 这样无需 Cloudflare Secret 权限即可配置，且 GitHub PAT 也不会进公开仓库文件。
let _cfg, _cfgAt = 0;
// KV 值防御性清洗：防止当初写入口令/token 时把 JSON 引号/空白一起存进去
const cleanKV = s => (s || '').trim().replace(/^"+|"+$/g, '');
async function cfg() {
  // 带 5 分钟 TTL 的缓存（2026-10-13 修复：此前永久缓存，KV 里轮换 GH_TOKEN/群口令后
  // 要等 isolate 重启才生效）
  if (!_cfg || Date.now() - _cfgAt > 300000) {
    // 2026-10-23：原来这里是 8 个串行 await（每个都是一次 KV get），冷启动时白白叠加 8 次 rtt。
    // 改成一次并发读取；语义完全不变（同样的键、同样的默认值、同样的 5 分钟缓存）。
    const [ghToken, groupPass, groupPass2, adminPass, assignPass, lim, limG1, limG2, consolePass, consoleRoPass] = await Promise.all([
      POOL.get('GH_TOKEN').catch(() => null),
      POOL.get('GROUP_PASS').catch(() => null),
      POOL.get('GROUP_PASS2').catch(() => null),
      POOL.get('ADMIN_PASS').catch(() => null),
      // 分配接口独立口令（2026-10-22）：/api/assign 会下发明文 CK，绝不能用发给全体成员的群口令，
      // 否则任何成员循环 job=0..N 就能把全池 MUSIC_U 拖走。未配置时该接口直接拒绝服务。
      POOL.get('ASSIGN_PASS').catch(() => null),
      POOL.get('POOL_LIMIT').catch(() => null),
      POOL.get('POOL_LIMIT_G1').catch(() => null),
      POOL.get('POOL_LIMIT_G2').catch(() => null),
      // 2026-11-11 v2.12：号池查看（/api/pool）要认控制台满权/只读码 —— 用户口径：
      // 同一个口令在控制台能看数据，在 APK 号池页却报「管理密码错误」太分裂。只加读、不加写。
      POOL.get('CONSOLE_PASS').catch(() => null),
      POOL.get('CONSOLE_RO_PASS').catch(() => null),
    ]);
    _cfg = {
      ghToken: cleanKV(ghToken),
      groupPass: cleanKV(groupPass),
      groupPass2: cleanKV(groupPass2),
      adminPass: cleanKV(adminPass),
      assignPass: cleanKV(assignPass),
      consolePass: cleanKV(consolePass),
      consoleRoPass: cleanKV(consoleRoPass),
      // 分群上限：2026-10-22 默认 500 → 1500，同日晚按「20 并发 + 24h 排队上限」下调到 1200
      // （KV 里 POOL_LIMIT_G1 / POOL_LIMIT_G2 仍可覆盖，改数字即时生效不用改代码）
      poolLimit: parseInt(cleanKV(lim), 10) || 1200,
      poolLimitG1: parseInt(cleanKV(limG1), 10) || 1200,
      poolLimitG2: parseInt(cleanKV(limG2), 10) || 500,
      owner: GH_OWNER,
      repo: GH_REPO,
    };
    _cfgAt = Date.now();
  }
  return _cfg;
}
const GH = async () => { const c = await cfg(); return { token: c.ghToken, owner: c.owner, repo: c.repo }; };
// ---- 群口令校验（GROUP_PASS）----
// 二群已独立（dingzhi 系统），主 worker 只认一群口令；带 group:2 的历史请求也按一群口令校验。
function groupPassCheck(c, body) {
  // 2026-10-20 应用户要求去掉一群群口令：恒放行（定制版 dingzhi 本就恒放行，两边一致）。
  // ⚠️ 文件末尾两个隐藏管理接口（/api/resync、/api/report_dead）用的是行内
  //    body.pass !== c.groupPass 校验，千万别改成走本函数，否则管理接口会对外敞开。
  return { ok: true };
}
// 危险管理接口的口令校验（2026-10-26 收紧）。
// 背景：/api/report_dead 能按名单删号（带 confirm 直接删）、/api/resync 能强制重推 12 个 Secrets，
// 而它们原来只认 GROUP_PASS —— 这个口令是发给全体成员的，还硬编码在号池管理工具/CK助手/安卓里，
// 等于半公开：任何群成员一个 POST 就能清空号池。
// 新口径：只要 KV 配了 ADMIN_PASS，这两个接口就【只】认 ADMIN_PASS；没配时才退回群口令（老部署兼容）。
function adminPassOk(c, pass) {
  const p = String(pass || '');
  if (c.adminPass) return p === c.adminPass;
  return !!(c.groupPass && p === c.groupPass);
}
// 跨群对穿口令（2026-10-26）：KV 键 PEER_KEY，两群存同一个 32 位随机值。
// 背景：对穿原来直接复用两边的群口令（dz 的 PEER_PASS 就是 hz 的 music2026），
// 于是「群口令」既能登记、又能读对端全池（含邮箱）、还能删改号。
// 新口径：配了 PEER_KEY 就只认它，完全不再接受群口令；没配时才退回旧的 PEER_PASS 对穿。
async function peerKey() { return cleanKV(await POOL.get('PEER_KEY')); }
async function peerPassOk(pass) {
  const k = await peerKey();
  const p = String(pass || '');
  if (k) return p === k;
  const old = cleanKV(await POOL.get('PEER_PASS'));
  return !!(old && p === old);
}
// ---- 分群计数辅助：历史条目没有 grp 字段的一律算一群 ----
const grpOf = e => (Number(e && e.grp) === 2 ? 2 : 1);
const groupLimitOf = (c, isG2) => (isG2 ? c.poolLimitG2 : c.poolLimitG1);
// 满员闸口的计数口径（2026-10-26 修复）：排除「已过期但还没被 pruneExpired 清掉」的号。
// 这些号到期后已不参与轮转，却仍然占着人数上限，导致满员提示比实际可登记名额早出现。
// 口径：exp 为空 / forever → 在册；形如 YYYY-MM-DD 且 < 今天 → 不计；其它异常格式按在册处理（保守）。
// 2026-11-05 补充：公益号（pub=1）不占登记名额。
// 原因：公益号从今天起一律 exp='forever'（到期降级时写死），forever 按上面的规则属于「在册」，
// 会永久占掉一个名额，越积越多最终把新登记的号挤掉。公益号本来就不是付费客户，不该占额度。
function activePoolSize(arr, today) {
  const t = today || beijingDate();
  let n = 0;
  for (const e of (arr || [])) {
    if (e && e.pub) continue;
    const x = String((e && e.exp) || '').trim();
    if (!x || x === 'forever') { n++; continue; }
    if (/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(x) && x < t) continue;
    n++;
  }
  return n;
}
async function ghPublicKey() {
  const g = await GH();
  const r = await fetch(`https://api.github.com/repos/${g.owner}/${g.repo}/actions/secrets/public-key`, { headers: { Authorization: `token ${g.token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'cron-relay-worker' } });
  return r.json();
}
// ---- blake2b (RFC 7693, BigInt 实现) ----
// GitHub Secrets API 要求 libsodium sealed box 格式：ephPub(32) || box(msg, nonce=blake2b24(ephPub||recipPub))
// 原实现缺临时公钥且 nonce 为零，是错的，任何密钥都写不进去。
const BLAKE2B_IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];
const BLAKE2B_SIGMA = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
  11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
  7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
  9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
  2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
  12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
  13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
  6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
  10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
];

function blake2b(input, outlen) {
  const MASK = (1n << 64n) - 1n;
  const rotr = (x, n) => ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK;
  const G = (v, a, b, c, d, x, y) => {
    v[a] = (v[a] + v[b] + x) & MASK;
    v[d] = rotr(v[d] ^ v[a], 32);
    v[c] = (v[c] + v[d]) & MASK;
    v[b] = rotr(v[b] ^ v[c], 24);
    v[a] = (v[a] + v[b] + y) & MASK;
    v[d] = rotr(v[d] ^ v[a], 16);
    v[c] = (v[c] + v[d]) & MASK;
    v[b] = rotr(v[b] ^ v[c], 63);
  };
  let h = BLAKE2B_IV.slice();
  h[0] ^= BigInt(outlen) | 0x01010000n;   // 无 key 的参数块
  const total = input.length;
  const nb = Math.max(1, Math.ceil(total / 128));
  const dv = new DataView(new ArrayBuffer(8));
  for (let i = 0; i < nb; i++) {
    const blk = new Uint8Array(128);
    blk.set(input.subarray(i * 128, (i + 1) * 128));
    const isLast = i === nb - 1;
    const t = BigInt(isLast ? total : (i + 1) * 128);
    // 消息字 m[0..15]，小端 64 位
    const m = [];
    for (let j = 0; j < 16; j++) {
      let w = 0n;
      for (let k = 7; k >= 0; k--) w = (w << 8n) | BigInt(blk[j * 8 + k]);
      m.push(w);
    }
    const v = new Array(16);
    for (let j = 0; j < 8; j++) v[j] = h[j];
    for (let j = 0; j < 8; j++) v[8 + j] = BLAKE2B_IV[j];
    v[12] ^= t;
    if (isLast) v[14] = ~v[14] & MASK;
    for (let r = 0; r < 12; r++) {
      const s = (r % 10) * 16;
      G(v, 0, 4, 8, 12, m[BLAKE2B_SIGMA[s]], m[BLAKE2B_SIGMA[s + 1]]);
      G(v, 1, 5, 9, 13, m[BLAKE2B_SIGMA[s + 2]], m[BLAKE2B_SIGMA[s + 3]]);
      G(v, 2, 6, 10, 14, m[BLAKE2B_SIGMA[s + 4]], m[BLAKE2B_SIGMA[s + 5]]);
      G(v, 3, 7, 11, 15, m[BLAKE2B_SIGMA[s + 6]], m[BLAKE2B_SIGMA[s + 7]]);
      G(v, 0, 5, 10, 15, m[BLAKE2B_SIGMA[s + 8]], m[BLAKE2B_SIGMA[s + 9]]);
      G(v, 1, 6, 11, 12, m[BLAKE2B_SIGMA[s + 10]], m[BLAKE2B_SIGMA[s + 11]]);
      G(v, 2, 7, 8, 13, m[BLAKE2B_SIGMA[s + 12]], m[BLAKE2B_SIGMA[s + 13]]);
      G(v, 3, 4, 9, 14, m[BLAKE2B_SIGMA[s + 14]], m[BLAKE2B_SIGMA[s + 15]]);
    }
    for (let j = 0; j < 8; j++) h[j] = (h[j] ^ v[j] ^ v[j + 8]) & MASK;
  }
  // 输出小端 64 位字，截断到 outlen
  const out = new Uint8Array(outlen);
  let o = 0;
  for (let j = 0; j < 8 && o < outlen; j++) {
    dv.setBigUint64(0, h[j], true);
    const tmp = new Uint8Array(dv.buffer);
    for (let k = 0; k < 8 && o < outlen; k++) out[o++] = tmp[k];
  }
  return out;
}

// ---- libsodium sealed box ----
function sealBox(msgU8, theirPub) {
  const eph = nacl.box.keyPair();
  const seed = new Uint8Array(64);
  seed.set(eph.publicKey, 0);
  seed.set(theirPub, 32);
  const nonce = blake2b(seed, 24);
  const boxed = nacl.box(msgU8, nonce, theirPub, eph.secretKey);
  const out = new Uint8Array(32 + boxed.length);
  out.set(eph.publicKey, 0);
  out.set(boxed, 32);
  return out;
}

async function ghPutSecret(name, value) {
  const g = await GH();
  const pk = await ghPublicKey();
  if (!pk || !pk.key || !pk.key_id) throw new Error('获取 GitHub Secrets 公钥失败（GH_TOKEN 无效/过期或仓库不对）：' + JSON.stringify(pk).slice(0, 120));
  const theirPub = b64dec(pk.key);
  const sealed = sealBox(utf8(value), theirPub);
  const r = await fetch(`https://api.github.com/repos/${g.owner}/${g.repo}/actions/secrets/${name}`, {
    method: 'PUT',
    headers: { Authorization: `token ${g.token}`, Accept: 'application/vnd.github+json', 'Content-Type': 'application/json', 'User-Agent': 'cron-relay-worker' },
    body: JSON.stringify({ encrypted_value: b64enc(sealed), key_id: pk.key_id }),
  });
  // 2026-10-22 加固：此前返回 status 但调用方不检查，422（值超 48KB）等失败被静默吞掉，
  // 导致最大分片连续 4 天写不进去没人发现。现在非 2xx 直接抛错让登记/resync 显式失败。
  // 2026-10-22 二次修复：Secret 写入成功时 GitHub 可能返回 201（新建）也可能是 204（更新）。
  // 只认 200/201 会把 204 判成失败 → pushPool 写完 NB_POOL_1 就抛错，后面 11 个槽位留着旧值，
  // 结果是号池被切成「新一片 + 旧十一 片」，比写不进去更危险。改为 2xx 一律算成功。
  if (!r.ok) {
    throw new Error(`写入 Secret ${name} 失败 HTTP ${r.status}（值过大或 GH_TOKEN 无权限）`);
  }
  return r.status;
}

// ---- 分片写回 NB_POOL_*（片数按号池体积自动伸缩，见 pushPool）----
// added 统一按北京时间记（2026-10-13 修复：此前用 UTC，北京 0-8 点登记的号会被提前一天入池，
// 与 run.py 的北京时间口径不一致）
function beijingDate() {
  return new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 10);
}
// 2026-10-30：入池时间精确到秒（'YYYY-MM-DD HH:MM:SS'，北京时间）。
// 兼容说明：老数据仍是纯 'YYYY-MM-DD'（长度 10），凡是按日期比较/解析的地方都取 slice(0,10)，
// 字符串比较天然成立（'2026-10-30 14:23' >= '2026-10-30'），所以 run.py / make_accounts.py
// 的 e.get("added","") < today 过滤规则无需改动。
function beijingDateTime() {
  return new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 19).replace('T', ' ');
}
// ---- 有效期（exp）：'YYYY-MM-DD' 到期即移除；无 exp / 'forever' = 永久 ----
function isExpiredEntry(e) {
  return !!(e && e.exp && e.exp !== 'forever' && String(e.exp) < beijingDate());
}
// 2026-10-29：单列 exp 的到期判定（给 D1 查重结果 / KV 回退路径用）
function isExpiredExp(exp) {
  return !!(exp && exp !== 'forever' && String(exp) < beijingDate());
}
function expDaysLeft(e) {
  if (!e || !e.exp || e.exp === 'forever') return Infinity;
  return Math.round((new Date(e.exp + 'T00:00:00Z') - new Date(beijingDate() + 'T00:00:00Z')) / 86400000);
}
function isSoonExpired(e) {
  const d = expDaysLeft(e);
  return d !== Infinity && d <= 3;
}
function beijingDatePlus(n) {
  return new Date(Date.now() + 8 * 3600 * 1000 + n * 86400 * 1000).toISOString().slice(0, 10);
}
// 2026-11-05：从指定日期起加 n 天（补号「继承原单」用：原单登记日 + 套餐天数 = 新到期日，
// 而不是从今天重算 —— 否则客户掉线补一次号就白赚剩下的月份）。
function datePlusFrom(base, n) {
  const s = String(base || '').slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return '';
  const d = new Date(s + 'T00:00:00Z');
  if (isNaN(d.getTime())) return '';
  return new Date(d.getTime() + (Number(n) || 0) * 86400000).toISOString().slice(0, 10);
}
// ====================================================================
// 2026-11-10：续费 / 补号 判定与有效期累加
// 背景（用户口径）：
//   · 号还在池里 = 续费（收钱、给客服提成）；号已经不在池 = 补号（免费、不给提成）。
//   · 补号只在「原套餐还在有效期内」才算；原套餐已过期再买 = 新登记。
//   · 只有「有效时长确实增加」才算续费单 —— 时长没涨就没有收益，不计台账。
// 旧行为（改成原地 UPDATE 之前）：DELETE 两行 + INSERT，added 重置成今天、exp 从今天重算
//   ⇒ ①提前续费被拒 ②提前续费白丢剩余天数 ③首周加速重复触发白烧一周播放量 ④台账分不清新/续。
// ====================================================================
// 从「今天 + 套餐天数」这个日期反推套餐天数（调用方构造 entry 时只给了 exp，没给 days）。
function planDaysOf(exp) {
  if (!exp || exp === 'forever') return 0;          // 永久套餐 → 0 天，不参与累加
  const s = String(exp).slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return 0;
  const d = Math.round((Date.parse(s + 'T00:00:00Z') - Date.parse(beijingDate() + 'T00:00:00Z')) / 86400000);
  return d > 0 ? d : 0;
}
// 续费后的新到期日。三档（见方案 §3.2）：
//   · 原到期日还在未来          → 原到期日 + 套餐天数（不从今天重算，剩余天数不丢）
//   · 原已过期 / 公益号(forever) → 今天 + 套餐天数
//   · 套餐是永久(days=0) 且原本就是真永久 → 保持 forever
// ⚠ 公益号的 exp 也是 'forever'，和「真永久套餐」长得一样，必须用 pub 区分（11-09 踩过这个坑）。
function renewExpCalc(oldExp, days, wasPub) {
  if (!(days > 0)) {
    // 套餐本身是永久：真永久号保持；公益号续「永久套餐」= 从今天起永久（本来也永久）
    return 'forever';
  }
  if (oldExp === 'forever' && !wasPub) return 'forever';   // 真永久，不再累加
  const base = (!oldExp || oldExp === 'forever' || isExpiredExp(oldExp)) ? beijingDate() : String(oldExp).slice(0, 10);
  return datePlusFrom(base, days) || beijingDatePlus(days);
}

function parseExpInput(x) {
  if (x == null || String(x).trim() === '') return { ok: true };
  const s = String(x).trim();
  if (s === 'forever' || s === '永久') return { ok: true, exp: 'forever' };
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return { ok: true, exp: s };
  if (/^\d{1,4}$/.test(s)) return { ok: true, exp: beijingDatePlus(parseInt(s, 10)) };
  return { ok: false };
}

// ====================================================================
// 客服标签 / 套餐档位（2026-10-27 新增）
// 背景：APK 与 EXE 都是客服用来登记的，人一多就分不清谁登记的；而「客服名字写死在软件里」
//       会导致每次人员变动都要重新打包 + 所有人重装。所以名单放在服务端，客户端每次登记前拉一份。
// 存放：D1 kv_misc 的 k='reg_cfg'（两群共用同一个 D1 库 → 只维护一份，两群自动一致）；
//       KV 同名键 REG_CFG 只作兜底镜像（D1 挂了才读）。
// 口径：accounts.agent 存客服名字原文，accounts.plan 存套餐「显示名」（1年/2年/永久），
//       统计按买的套餐算，不按剩余天数算（exp 可改可续，会漂）。
// ====================================================================
const REG_CFG_KEY = 'reg_cfg';
const REG_CFG_KV = 'REG_CFG';
// 2026-11-05：套餐加 price（单价，元）并补「半年」档。
// price 只用于控制台「月度结算」算钱，不参与播放/有效期任何判定；
// 0 元或缺省 = 该档位没定价，结算页会把它单独列成「待补价」，绝不按 0 元混进合计。
const REG_CFG_DEFAULT = {
  agents: ['徐'],
  // 2026-11-06：每个客服的售后 QQ 群号（登记成功邮件 / 到期提醒邮件里用）。
  // groups[客服名] = 群号（纯数字字符串）；default_group = 老号没带客服名时的兜底群。
  // 都可以在控制台「客服名单」里改：名单框一行「客服名|群号」，不带竖线=没群号。
  groups: {},
  default_group: '',
  // 档位顺序 = 客户端下拉顺序，从短到长排。
  plans: [
    { key: '1m', label: '1月', days: 30, price: 3 },
    { key: '6m', label: '半年', days: 180, price: 10 },
    { key: '1y', label: '1年', days: 365, price: 15 },
    { key: '2y', label: '2年', days: 730, price: 20 },
    { key: 'forever', label: '永久', days: 0, price: 80 },
  ],
};

// 客服名：去空白/控制字符/引号，最长 16 字。不校验是否在名单内 ——
// 名单随时会改，旧客户端可能还在提交已删掉的名字，直接拒绝会让登记全线失败。
function normAgent(x) {
  return String(x == null ? '' : x).replace(/[\u0000-\u001f\u007f"'<>]/g, '').trim().slice(0, 16);
}

function normRegCfg(o) {
  const out = { agents: [], groups: {}, default_group: '', plans: [] };
  const src = (o && typeof o === 'object') ? o : {};
  for (const a of (Array.isArray(src.agents) ? src.agents : [])) {
    const v = normAgent(a);
    if (v && !out.agents.includes(v)) out.agents.push(v);
  }
  // 2026-11-06：售后群号。只保留还挂在名单里的客服（名单里删了人，群号跟着清）；
  // 群号只留数字，5~20 位（QQ 群号现状 9~10 位，留点余量），非法就丢弃。
  if (src.groups && typeof src.groups === 'object' && !Array.isArray(src.groups)) {
    for (const k of Object.keys(src.groups)) {
      const nm = normAgent(k);
      const gp = String(src.groups[k] == null ? '' : src.groups[k]).replace(/[^0-9]/g, '');
      if (nm && gp.length >= 5 && gp.length <= 20 && out.agents.includes(nm)) out.groups[nm] = gp;
    }
  }
  const dg = String(src.default_group == null ? '' : src.default_group).replace(/[^0-9]/g, '');
  if (dg.length >= 5 && dg.length <= 20) out.default_group = dg;
  for (const p of (Array.isArray(src.plans) ? src.plans : [])) {
    if (!p || typeof p !== 'object') continue;
    const label = String(p.label || '').trim().slice(0, 8);
    if (!label) continue;
    const days = Math.max(0, Math.min(36500, parseInt(p.days, 10) || 0));
    const key = String(p.key || label).trim().slice(0, 16) || label;
    if (out.plans.some(x => x.key === key)) continue;
    // 2026-11-05：单价（元）。缺省/非法 = -1（未定价），不是 0 —— 0 会被结算当成免费，
    // 让一整档的收入凭空消失；-1 会显式落到「待补价」里等人填。
    let price = Number(p.price);
    if (p.price === undefined || p.price === null || String(p.price).trim() === ''
        || !isFinite(price) || price < 0) {
      // ⚠ 老配置（11-05 之前存的 reg_cfg）里根本没有 price 字段。这里按内置默认价的同名档位兜底，
      // 否则升级 Worker 的那一刻，全群 4 个档位会一起变成「未定价」，月度结算全是待补价。
      const dft = REG_CFG_DEFAULT.plans.find(x => x.label === label);
      price = dft ? dft.price : -1;
    }
    price = Math.round(price * 100) / 100;
    out.plans.push({ key: key, label: label, days: days, price: price });
  }
  if (!out.agents.length) out.agents = REG_CFG_DEFAULT.agents.slice();
  if (!out.plans.length) out.plans = REG_CFG_DEFAULT.plans.map(p => ({ key: p.key, label: p.label, days: p.days, price: p.price }));
  return out;
}

// 客服 → 售后群号（2026-11-06）。优先该客服自己配的群；没配就用 default_group；都没有回 ''。
function agentGroupOf(cfg, agent) {
  const c = cfg || {};
  const nm = normAgent(agent);
  if (nm && c.groups && c.groups[nm]) return String(c.groups[nm]);
  return String(c.default_group || '');
}

// 套餐显示名 → 单价（元）。返回 -1 表示没定价（结算页单列，不计入合计）。
function planPrice(cfg, label) {
  const s = String(label == null ? '' : label).trim();
  if (!s) return -1;
  const p = ((cfg && cfg.plans) || []).find(it => it.key === s || it.label === s);
  if (!p) return -1;
  return (typeof p.price === 'number' && p.price >= 0) ? p.price : -1;
}

// 读配置：D1 → KV → 内置默认。任何异常都不抛，绝不阻塞登记。
async function regCfg() {
  let raw = null;
  if (d1ok()) {
    try {
      const rows = await d1All('SELECT v FROM kv_misc WHERE k=?', [REG_CFG_KEY]);
      if (rows && rows.length) raw = rows[0].v;
    } catch (e) { console.error('读 reg_cfg(D1) 失败:', e && e.message); }
  }
  if (!raw) {
    try { raw = await POOL.get(REG_CFG_KV); } catch (e) {}
  }
  let o = null;
  try { o = raw ? JSON.parse(raw) : null; } catch (e) { o = null; }
  return normRegCfg(o);
}

// 写配置：控制台「客服名单」用（只读口令进不来，见 /api/console/cfg）。D1 为主，KV 兜底镜像。
async function saveRegCfg(o) {
  const cfgN = normRegCfg(o);
  const s = JSON.stringify(cfgN);
  let d1 = false;
  if (d1ok()) {
    d1 = await d1Run('INSERT INTO kv_misc (k,v,updated_at) VALUES (?,?,?) ' +
      'ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated_at=excluded.updated_at',
      [REG_CFG_KEY, s, new Date().toISOString()]);
  }
  try { await POOL.put(REG_CFG_KV, s); } catch (e) {}
  return { ok: !!d1, cfg: cfgN };
}

// 把客户端传来的「套餐」（key 或显示名都认）解析成 {key,label,exp}
// 2026-11-11：返回值补 days（原始天数），join_manual 的「套餐与 exp 打架以套餐为准」
// 兜底要用；只是加字段，老调用点不受影响。
function planOf(cfg, x) {
  const s = String(x == null ? '' : x).trim();
  if (!s) return null;
  const p = (cfg.plans || []).find(it => it.key === s || it.label === s);
  if (!p) return null;
  return { key: p.key, label: p.label, days: p.days, exp: (p.days > 0 ? beijingDatePlus(p.days) : 'forever') };
}
// 到期账号清理：删独立键 + 记墓碑 + 刷 master + 回推 GitHub Secrets（只在有过期时才写）
// 到期处理：2026-11-05 起不再删号，改成「降级为公益号」保留在池子里。
// 为什么改：到期的号直接删掉会让池子突然缩水（原本它在帮别人听），而且号主的记录全没了、
//   续费还得重新走一遍登记；降级成公益号后：自己的歌不再分给别人听（pub=1 天然如此），
//   但仍然帮别人听，号主随时续费（重新登记同一个号）就恢复普通号。
// 2026-11-05 用户要求：降级时直接写成 exp='forever'（公益号永久有效）+ 清空 email。
//   为了防止永久有效的号白占登记名额，activePoolSize 已改成「pub=1 不计入」。
async function pruneExpired() {
  const master = await mergePool();
  // 已经是公益号的跳过，否则每天都会把同一批号重复写一遍
  const dead = master.filter(e => isExpiredEntry(e) && !e.pub);
  if (!dead.length) return { master: master, count: 0 };
  await Promise.all(dead.map(async e => {
    e.pub = 1;
    // 2026-11-05 用户要求：公益号一律「永久有效」+ 清掉邮箱（不再发任何提醒），
    // 就这么挂着帮别人听，直到 cookie 失效被判死删除为止。
    // 设 forever 后必须配 activePoolSize 的「pub 不占名额」，否则到期号会永久白占额度。
    e.exp = 'forever';
    e.email = '';
    /* 2026-11-10：KV 写必须容错。KV 免费写额度只有 1000/天，写满时 POOL.put 抛异常 ——
       原来这里没有 try，一个号写失败就把整批 Promise.all 打断（后面的到期号既不降级也不写 D1），
       表现为「到期号一直挂在池里、号主收不到任何通知」。D1 才是权威，KV 失败不影响降级。 */
    try { await POOL.put(entryKeyOf(e), JSON.stringify(e)); }
    catch (er) { console.error('KV 写到公益号失败（继续走 D1）:', e && (e.name || e.uid)); }
    if (!(await d1Upsert(e))) console.error('D1 到期降级公益号失败:', e && (e.name || e.uid));
  }));
  // 审计留档：dead_log 里记一条 expired_pub（不是删除，控制台「删号记录」里能看出是到期降级）
  await d1LogDead(dead, 'expired_pub');
  // 2026-11-05：到期降公益后【不再发提醒】（用户口径：公益号不需要再提醒）。
  // 原来这里会给号主发 kind='expired' 的「到期了快续费」，现在公益号本身是永久的，
  // 发信只会变成噪音。要恢复的话把下面这行 try 解注释即可。
  // try { for (const e of dead) await d1QueueNotice(e, 'expired'); } catch (e) { console.error('通知队列写入失败:', e && e.message); }
  // 池内容变了（pub 变了）→ 刷新应急快照。号没删，所以不推 Secrets。
  try { await refreshPoolSnap(); } catch (e) {}
  return { master: master, count: dead.length };
}

/* ============================================================================
   2026-11-09：CK 失效「超时自动清理」（用户要求）
   ----------------------------------------------------------------------------
   要解决的问题：/api/report_dead 的「删号前复核」（B 方案：用活号 CK 查网易主页）
   碰到「CK 死了、但网易账号还在」时只打 relogin_at + 发一封「请重新登记」，号留在库里。
   而 buildPlanFrom 里 `r.relogin → idle` 把它摘出听众环 ⇒ 客户端从此不再上报它
   ⇒ report_dead 永远收不到它 ⇒ 逻辑上没有任何路径会再处理它。这就是「号主不理就永远挂着」。
   （11-09 手工清掉的那 6 个 dz 号，从 11-04 收到通知一直挂到 11-09，正是卡在这一步。）

   口径（用户 2026-11-09 定）：relogin_at 非空（= 已经通知过号主）且距今 ≥ RELOGIN_TTL_DAYS
   （KV 键 RELOGIN_TTL_DAYS 可配，默认 7 天）→ 直接删号 + 入 dead_notice 队列发信。

   删除链路严格照抄 report_dead 的成功路径（铁律 3：先删 D1，删成功才动 KV / 墓碑 / 队列 / 流水）：
     d1Delete 成功 → 删 entry 键 → 写墓碑 dead_log → dead_notice 入队 → dead_log 记流水
     → pushPool(剩余) → refreshPoolSnap
   为什么挂在 CF 每日 cron 而不是请求路径：这些号已不在 plan 里，没有任何请求会顺便触发它，
   只有定时器靠得住。hz 主 cron 顺带通过 /api/relogin_sweep 让对端（dz，无 scheduled）也跑一遍。
   ============================================================================ */
async function reloginTtlDays() {
  // 不做成常量：想改天数直接往 KV 加 RELOGIN_TTL_DAYS 即可，不用改代码重部署。
  try {
    const v = Number(cleanKV(await POOL.get('RELOGIN_TTL_DAYS')));
    if (v > 0) return v;
  } catch (_e) {}
  return 7;
}

async function pruneStaleRelogin(days) {
  if (!d1ok()) return { ok: false, msg: 'D1 未绑定' };
  const ttl = Number(days) > 0 ? Number(days) : await reloginTtlDays();
  const cutoff = Date.now() - ttl * 86400000;
  // 只拉「已通知过」的行：通常个位数，全池扫一趟也就 700 行/天。
  // 读失败必须当失败（铁律 3c）—— 否则会被当成「没有超时号」而静默永不清理。
  const rows = await d1All("SELECT uid,name,email,relogin_at FROM accounts WHERE pool=? AND relogin_at IS NOT NULL AND relogin_at<>''",
    [POOL_NAME]);
  if (!rows) return { ok: false, msg: 'D1 查询失败（accounts 读不到）' };
  const stale = rows.filter(r => {
    const t = Date.parse(String(r.relogin_at || ''));
    return !isNaN(t) && t <= cutoff;
  });
  if (!stale.length) return { ok: true, ttl: ttl, checked: rows.length, removed: 0, names: [] };

  const master = await mergePool();
  const gone = [], fail = [];
  for (const r of stale) {
    // 优先用池里的完整条目（entryKeyOf / pushPool 过滤都要它），找不到才退化到最小对象
    const full = master.find(e => String(e.uid || '') === String(r.uid || '')
                                  && (!r.name || String(e.name || '') === String(r.name)))
                 || { uid: r.uid, name: r.name, email: r.email };
    let ok = false;
    try { ok = (await d1Delete(full)) === true; } catch (_e) { ok = false; }
    (ok ? gone : fail).push(full);
  }
  await Promise.all(gone.map(async e => { try { await POOL.delete(entryKeyOf(e)); } catch (_e) {} }));
  const ekeys = gone.map(entryKeyOf);
  if (ekeys.length) {
    try {
      const log = new Set(await getDeadLog());
      for (const k of ekeys) log.add(k);
      await POOL.put('dead_log', JSON.stringify([...log].slice(-500)));
    } catch (_e) {}
  }
  // kind 单独记 relogin_timeout：控制台「删号记录」能区分「7 天没理自动清」和「当场判死」。
  let queued = 0;
  for (const e of gone) { try { if (await d1QueueNotice(e, 'relogin_timeout')) queued++; } catch (_e) {} }
  await d1LogDead(gone, 'cookie_invalid');   // 删号原因口径仍只有 cookie_invalid / manual 两种
  const gs = new Set(ekeys);
  try { await pushPool(master.filter(e => !gs.has(entryKeyOf(e)))); } catch (_e) {}
  try { await refreshPoolSnap(); } catch (_e) {}
  const nmOf = e => e.name || String(e.uid || '');
  const names = gone.map(nmOf), failed = fail.map(nmOf);
  if (names.length || failed.length) {
    console.log('relogin 超时清理（TTL ' + ttl + ' 天）：检查 ' + rows.length + ' 个已通知号，删除 ' + names.length
      + (names.length ? '（' + names.join('、') + '）' : '')
      + (failed.length ? '，删除失败 ' + failed.length + ' 个下轮重试（' + failed.join('、') + '）' : ''));
  }
  return { ok: true, ttl: ttl, checked: rows.length, removed: names.length, queued: queued,
           names: names, failed: failed };
}
async function gzipU8(u8) {
  // 2026-10-22：分片 JSON 先 gzip 再 base64。此前直接 base64 JSON，分片 45000 字符
  // 封装后约 1.78 倍膨胀到 ~80KB，超过 GitHub Secret 48KB 上限 → 最大那片恒被 422
  // 拒绝（且空槽都成功，表面看 resync 正常），老账号变更自 10-18 起没进过 Actions 号池。
  const cs = new CompressionStream('gzip');
  const stream = new Blob([u8]).stream().pipeThrough(cs);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

// 2026-10-22：Secrets 分片降级为「只读回退备份」，默认不再随每次登记/删除重写。
// 原因：一次 pushPool = 12 次 ghPutSecret（每次 X25519 + sealed box + 加密 + PUT），
// 是整个 worker 最大的 CPU 消耗；而所有读者（run.py / make_accounts.py / run.yml plan）
// 现在都先走 D1（/api/assign、/api/pool_stat），只有 D1 完全不可用时才回退 Secrets。
// 紧急需要重推一份全量快照：KV 里把 PUSH_SECRETS 设为 '1'，或直接调 /api/resync（强制推）。
let _pushOn = null, _pushOnAt = 0;
async function pushPoolEnabled() {
  if (_pushOn !== null && Date.now() - _pushOnAt < 60000) return _pushOn;
  try { _pushOn = (cleanKV(await POOL.get('PUSH_SECRETS')) === '1'); }
  catch (e) { _pushOn = false; }
  _pushOnAt = Date.now();
  return _pushOn;
}

async function pushPool(entries, force) {
  if (!force && !(await pushPoolEnabled())) return { skipped: true, count: entries.length };
  const CHUNK_MAX = 40000;  // 单片原始 JSON 字符数；实测 gzip≈0.52 字节/字符（CK hex 不可压缩），b64+sealed 后 ~37KB < 48KB
  // 2026-11-01：片数不再写死 12。按号池实际体积自动算（ceil(总字符 / CHUNK_MAX)）：
  // 池子涨多少片就自动多写几片，读取端（run.py / make_accounts.py / run.yml plan）改成动态扫 env，
  // 两端都不需要再改代码。SLOT_MAX 只是「异常数据别把 GitHub API 打爆」的护栏，
  // 40 片 × 4 万字符 ≈ 160 万字符 ≈ 1700 号，远高于注册上限 1200，实际用不满。
  const SLOT_MAX = 40;
  const chunks = [];
  let cur = [];
  let size = 0;
  for (const e of entries) {
    const s = JSON.stringify(e).length + 1;
    if (size + s > CHUNK_MAX && cur.length) { chunks.push(cur); cur = []; size = 0; }
    cur.push(e); size += s;
  }
  if (cur.length) chunks.push(cur);
  if (chunks.length > SLOT_MAX) {
    const dropped = chunks.slice(SLOT_MAX).reduce((n, c) => n + c.length, 0);
    console.error(`号池 ${entries.length} 条超出 ${SLOT_MAX} 片 Secrets 容量，超出的 ${dropped} 条未写入，请扩容或清理！`);
  }
  const writeN = Math.min(chunks.length, SLOT_MAX);
  // 上次写了几片（KV POOL_SLOTS）。号池收缩时必须把高位槽写成 '[]' 清干净，
  // 否则读取端会把上一版遗留的高位分片也并进来（等于凭空多出一批旧号）。
  // 初值 12 = 改造前固定片数，保证第一次跑时能清掉 13..12 之外可能存在的残留。
  let prevN = 12;
  try {
    const p = parseInt(cleanKV(await POOL.get('POOL_SLOTS')) || '', 10);
    if (p > 0) prevN = p;
  } catch (e) {}
  const totalN = Math.max(writeN, prevN);
  for (let i = 0; i < totalN; i++) {
    const name = `NB_POOL_${i + 1}`;
    if (i < writeN) await ghPutSecret(name, b64enc(await gzipU8(utf8(JSON.stringify(chunks[i])))));
    else await ghPutSecret(name, b64enc(await gzipU8(utf8('[]'))));
  }
  try { await POOL.put('POOL_SLOTS', String(writeN)); } catch (e) {}
  return { slots: writeN, count: entries.length };
}

// ---- 号池并发安全 ----
// 真实来源 = 每条账号一个独立 KV 键（entry: 前缀）。单键写入/删除互不干扰，从根上消除
// "整表读-改-写"竞态（此前多人同时登记会整表互相覆盖，表现为号池条目凭空减少）。
// master 键降级为合并视图缓存：即使被并发写坏，下次 mergePool 会从独立键自动重建。
function entryKeyOf(e) {
  return e && e.uid != null && String(e.uid) !== ''
    ? 'entry:u' + String(e.uid)
    : 'entry:n' + encodeURIComponent(String((e && e.name) || 'unknown'));
}

// 删除墓碑：report_dead/管理删除过的账号键记录在 dead_log，防止
// ① master 边缘缓存旧快照（≤60s）把已删条目"复活"回填；
// ② 刚被清理的成员在缓存窗口内重新登记被误判"已登记"。重新登记成功后自动移除墓碑。
async function getDeadLog() {
  try { return JSON.parse(await POOL.get('dead_log') || '[]') || []; } catch (e) { return []; }
}

async function mergePool() {
  // 读走 D1：一条 SELECT 取代原来的「1 次 list + N 次 POOL.get」。
  // 号池 213 个号时，这一步从 214 次 KV 读 / 214KB 传输降到 1 次 D1 查询。
  const d1 = await d1Pool();
  if (d1) return d1;
  return await mergePoolKV();
}

// 纯 KV 版合并（不做 D1 优先）。
// 用途：/api/d1_sync 必须拿「KV 的真实内容」去对齐 D1，走 mergePool 会变成 D1 对齐 D1，没有意义。
async function mergePoolKV() {
  // ① 单键快照优先（2026-10-22 第三批）：1 次 KV 读拿到全池。
  //    原来的「list + 逐键 get」在 1200 个号时是 1201 次外部操作，超过单次 invocation 的
  //    1000 次外部操作上限 → 兜底路径必然失败，灾备形同虚设。
  try {
    const snap = await POOL.get(poolSnapKey());
    if (snap) {
      const arr = JSON.parse(snap);
      if (Array.isArray(arr) && arr.length) {
        const dead = new Set(await getDeadLog());
        return arr.filter(e => !dead.has(entryKeyOf(e)));
      }
    }
  } catch (e) { console.error('号池快照读取失败，回退 entry 键:', e && e.message); }

  // ② 没有快照 → 退回 entry: 独立键（真实来源），但必须限制读取条数：
  //    1 次 dead_log + 1~2 次 list + 最多 900 次 get < 1000（单次 invocation 外部操作上限）。
  const MAX_KEYS = 900;
  const keyNames = [];
  let cursor, truncated = false;
  do {
    const page = await POOL.list({ prefix: 'entry:', limit: 1000, cursor });
    for (const k of page.keys) {
      if (keyNames.length >= MAX_KEYS) { truncated = true; break; }
      keyNames.push(k.name);
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor && !truncated);
  if (truncated) console.error('KV 兜底：entry 键超过 ' + MAX_KEYS + ' 个，已截断（单次调用 1000 次外部操作上限）');
  // 2026-10-22：master 是 ~200KB 的旧合并缓存，以前每次都先读它再合并，等于每次回退都白传一次
  // 大对象 + 解析。只在「一个 entry: 键都读不到」的极端情况（首次迁移 / 键被误删）才读它兜底。
  let base = [];
  if (!keyNames.length) {
    try { base = JSON.parse(await POOL.get('master') || '[]') || []; } catch (e) {}
  }
  const deadLog = new Set(await getDeadLog());
  const byKey = new Map();
  for (const e of base) {
    if (deadLog.has(entryKeyOf(e))) continue;   // 墓碑内的缓存残留不参与（已删账号不复活）
    byKey.set(entryKeyOf(e), e);                // 顺带去重历史重复条目
  }
  const vals = await Promise.all(keyNames.map(n => POOL.get(n)));
  let changed = false;
  for (let i = 0; i < keyNames.length; i++) {
    if (!vals[i]) { changed = true; continue; }        // 键已删但 list 索引未收敛，跳过
    let v; try { v = JSON.parse(vals[i]); } catch (e) { continue; }
    if (!byKey.has(keyNames[i])) { byKey.set(keyNames[i], v); changed = true; }
  }
  const merged = [...byKey.values()];
  // 回填：master 有但独立键缺失的老数据（首次升级时一次性迁移，之后不再触发）
  const listed = new Set(keyNames);
  await Promise.all(merged
    .filter(e => !listed.has(entryKeyOf(e)))
    .map(e => POOL.put(entryKeyOf(e), JSON.stringify(e))));
  if (changed || merged.length !== base.length) {
    // master 缓存不再回写（2026-10-22）：读者全走 D1，entry: 独立键才是权威
  }
  return merged;
}

// 读全池，并保证包含「刚写入的那一条」。
// 用途：登记成功后要推 Secrets 分片，如果 D1 镜像写失败或读延迟，这个新号就会从分片里消失，
// 第二天签到/发动态就漏号。这里按主键再兜一次，成本只是一次字符串比较。
async function mergePoolEntry(entry, ekey) {
  const list = await mergePool();
  const k = ekey || entryKeyOf(entry);
  if (!list.some(e => entryKeyOf(e) === k)) list.push(entry);
  return list;
}

// 2026-11-10：查这个号最近一笔台账（判定「补号」用）。
// 号已经被删（掉线）时 accounts 里查不到，只能从 ledger 找原单的到期日：
//   · 原单还在有效期内 → 客户没享受完，这次是补号（免费，有效期继承原单）
//   · 原单已过期       → 客户的钱已经用完，这次是重新买（按新登记处理）
// 返回 null = 查不到 / D1 读不了（读不了时按「新登记」走，绝不多送时长）。
async function d1FindLastOrder(uidKey, name, exp) {
  if (!d1ok()) return null;
  /* 2026-11-10：加 name —— 补登链接要「自动带出上次的手机号」，来源就是台账的 name。
     台账没有 email 列，所以邮箱没法预填（那是客户现在能收到信的那个，必须自己填）。
     2026-11-10 晚：第三参 exp —— 控制台「选原单」会连同那一笔的到期日一起传上来。
     原本不管前端选第几笔，这里一律返回 ORDER BY day DESC 的最近一笔，客服看着是
     「2026-09-01 那单」、实际按「2026-11-01 那单」算续费基数，静默错单。
     只接受干净的日期串或 forever（避免把前端字符串直接拼进 SQL）。 */
  const expF = /^\d{4}-\d{2}-\d{2}$/.test(String(exp || '')) ? String(exp)
    : (String(exp || '') === 'forever' ? 'forever' : '');
  const tail = (expF ? ' AND exp=? ' : ' ') + 'ORDER BY day DESC, id DESC LIMIT 1';
  const SQL = 'SELECT day,start,exp,agent,plan,uid,name,at FROM ledger WHERE pool=? AND ';
  let rows = null;
  if (uidKey) {
    const ps = expF ? [POOL_NAME, String(uidKey), expF] : [POOL_NAME, String(uidKey)];
    rows = await d1All(SQL + 'uid=?' + tail, ps);
  }
  if ((!rows || !rows.length) && String(name || '')) {
    const ps = expF ? [POOL_NAME, String(name), expF] : [POOL_NAME, String(name)];
    rows = await d1All(SQL + 'name=?' + tail, ps);
  }
  return (rows && rows.length) ? rows[0] : null;
}

async function addEntry(entry) {
  // 有效期默认 2 年（730 天），管理端可随时修改（exp=YYYY-MM-DD，forever=永久）
  if (!entry.exp) entry.exp = beijingDatePlus(730);
  const ekey = entryKeyOf(entry);
  const uidKey = entry.uid != null ? String(entry.uid) : null;

  // ---- D1 快速路径：一次 SELECT 完成查重（原路径要把 213 个 entry 键全读一遍）----
  if (d1ok()) {
    // uid 为空的（用 name 占位的老号）只能按 name 查。不带 uid 时不要拼那个 ? 占位符，
    // 否则得传哨兵值，而 D1 绑定含 NUL 的字符串会报错 → 白走一次 KV 回退。
    // 2026-11-08：改为 d1FindDup（两条单条件查询，各走索引），实测 623 行 → 1~2 行。
    const dup = await d1FindDup(uidKey, entry.name);
    if (dup === null) {
      console.error('D1 查重失败，回退 KV 全量查重');
    } else {
      /* 2026-11-10 重构（用户口径）：不再「删除重建」，改成「判定类型 + 原地更新」。
         kind = new   首次进池（号池 +1，收钱，给客服提成）
                renew 号还在池里（含公益号/未到期），收钱、给提成，有效期在原基础上累加
                fix   号已经不在池（掉线被删），但原套餐还在有效期内 → 免费补回，不给提成
         旧逻辑是 DELETE 两行 + INSERT，把 added 重置成今天、exp 从今天重算，副作用四个：
           ①提前续费被拒 ②白丢剩余天数 ③首周加速重复触发白烧一周播放量 ④台账分不清新/续。 */
      let kind = 'new';
      let keepRow = null;
      let hist = null;                                            // 台账原单（补登/续费要用）
      /* 2026-11-10 修复：把「已判死等重登」的行（relogin_at 非空）与「正常在池」的行分开。
         relogin 行 = CK 已确认失效、已通知号主重登，留在 accounts 里只是等 RELOGIN_TTL_DAYS
         （默认 7 天）超时清理；buildPlanFrom 会 r.relogin → idle 把它摘出听众环，
         **它其实已经不参与播放了**。原来不区分，这种号被判成「还在池里正常运行」，两个反向错误：
           · 客服发补登链接来重登 → 撞「这个号还在号池里正常运行，不需要补登」（文案与事实相反）
           · 不指定类型 → 判成 renew 收钱，客户只是重登却白付一次套餐
         现在只有 live 代表「在池运行」，dead 的口径等同「不在池」→ 走补登（免费、继承原单）。 */
      const live = dup.filter(d => d && !d.relogin_at);
      const dead = dup.filter(d => d && d.relogin_at);
      if (live.length) {
        // 号还在池里 → 续费。优先按 uid 认（同一个网易号），没有再看 name 命中的行。
        const byUid = uidKey ? live.find(d => d && d.uid != null && String(d.uid) === uidKey) : null;
        const others = byUid ? live.filter(d => String(d.uid) !== String(byUid.uid)) : live.slice();
        // 同一个手机号还挂着另一个「未到期的非公益号」→ 一号多登，仍按旧口径拒绝。
        if (!byUid && others.some(d => d && !d.pub && !isExpiredExp(d.exp))) {
          return { ok: false, msg: '该账号已登记过（每个账号限登记一首歌），无需重复登记。' };
        }
        keepRow = byUid || others[0] || null;
        kind = 'renew';
      } else {
        // 号不在池里（或只剩已判失效的行）：看台账原单还在不在有效期内 —— 在 = 客户没享受完，这是补号
        hist = await d1FindLastOrder(uidKey, entry.name);
        if (hist && hist.exp && hist.exp !== 'forever' && !isExpiredExp(hist.exp)) {
          kind = 'fix';
          keepRow = { exp: hist.exp, added: hist.start || hist.day || '', pub: 0 };
        } else if (dead.length) {
          // 号在库里但已判失效、台账又查不到有效原单 → 仍按补登放行：
          // 到期日/入池日取号上的真实值 —— 保留剩余时长，也别把首周加速（added）重置掉。
          const dr = (uidKey && dead.find(d => d && String(d.uid) === uidKey)) || dead[0];
          kind = 'fix';
          keepRow = { exp: String(dr.exp || '').slice(0, 10) || beijingDate(),
                      added: String(dr.added || ''), pub: 0 };
        }
      }

      /* ===== 2026-11-10：链接上带了类型就以链接为准 =====
         客服在发链接那一刻就知道这一单收不收钱（补登免费 / 续费收钱），比「号在不在池里」
         可靠得多 —— 号掉线了但客户付了续费，光看数据会被判成免费补登，客户白付钱、
         客服白干；反过来把新客户标成补登就白送一个套餐。 */
      const _force = entry.__force || null;
      if (_force && _force.kind === 'fix') {
        /* 只有「正常在池」的行才能挡住补登（live）。只剩 relogin 行时放行 ——
           那种号的 CK 已确认失效，补登正是它唯一的出路；原来用 dup.length 判断，
           于是「CK 死了但还没被清」的号永远补不回来，提示还说它「正常运行」。 */
        if (live.length) {
          return { ok: false, msg: '这个号还在号池里正常运行，不需要补登（要延长有效期请走续费）。' };
        }
        // 到期日优先级：链接上带的原单到期日 → 台账原单 → 号上现有的到期日（relogin 行的 exp）
        const fexp = String(_force.exp || (hist && hist.exp) || (keepRow && keepRow.exp) || '').slice(0, 10);
        if (!fexp) return { ok: false, msg: '找不到原单到期日，这次补登没做成，请联系管理员' };
        kind = 'fix';
        keepRow = { exp: fexp,
          added: String((keepRow && keepRow.added) || (dead[0] && dead[0].added)
                        || (hist && (hist.start || hist.day)) || '').slice(0, 19),
          pub: 0 };
      } else if (_force && _force.kind === 'renew' && !live.length) {
        // 号已掉线（或只剩 relogin 行），但这一单是付了钱的续费：以原单到期日为基准累加，不能判成免费补登
        const bexp = String(_force.exp || (hist && hist.exp) || (keepRow && keepRow.exp) || '').slice(0, 10) || beijingDate();
        if (bexp === 'forever') {
          return { ok: false, msg: '这个号原来是永久套餐，续费不会增加时长；直接发「补登」链接免费补回即可。' };
        }
        kind = 'renew';
        keepRow = { exp: bexp, added: String((hist && (hist.start || hist.day)) || '').slice(0, 19), pub: 0 };
      }
      delete entry.__force;                                       // 类型标签不能写进 KV/D1

      /* 2026-11-10 修复：返回值 days 原来是 planDaysOf(entry.exp) —— 续费时那已经是
         「续费之后的剩余总天数」，不是「本次买了多少天」，语义是错的（exp 已被 newExp 覆盖）。
         现在统一成「这一单买到的天数」：new=套餐天数 / renew=本次套餐天数 / fix=0（免费）。 */
      let boughtDays = 0;
      if (kind === 'renew') {
        const days = planDaysOf(entry.exp);                       // 本次买的套餐天数
        boughtDays = days;
        /* 2026-11-10 晚：防「超时重试」被当成第二次续费（真实事故）。
           手机版 APK 的原生登记通道读超时只有 20 秒，而这条链路要打 3~4 次外部接口 + 写 D1 +
           整池重建灾备快照，常态 8~15 秒，弱网必然撞线。撞线只是客户端没等到回执 ——
           服务端其实已经写库了。客服看到「登记失败」就再点，于是每次都被判成「号还在池里 = 续费」，
           有效期一次次 +730 天（11-10 21:38 实例：2 年套餐被点了 5 次，直接变成 3650 天）。
           判据用台账而不看 accounts.updated_at：台账只在真登记时写，改邮箱/改 CK 不会动它，
           不会误伤；而且 ledger 的 (pool,uid,day) 唯一、同日多笔会合并成一行、at 取最后一次，
           所以「最近一笔在 10 分钟内」就等于「刚刚登记成功过」。
           10 分钟窗口对正常业务无影响（同一个人一天内连买两单套餐本来就不存在）。
           查不到（D1 读失败）时照旧放行，不因为校验不了就把人挡在外面。 */
        const _last = await d1FindLastOrder(uidKey, entry.name);
        const _lastAt = _last ? String(_last.at || '') : '';
        const _lt = _lastAt ? Date.parse(_lastAt.replace(' ', 'T') + '+08:00') : 0;
        if (_lt && Date.now() - _lt < 10 * 60 * 1000) {
          const _mins = Math.max(1, Math.round((Date.now() - _lt) / 60000));
          return { ok: false, msg: '这个号 ' + _mins + ' 分钟前已经登记成功过（上一次多半只是软件没等到回执，'
            + '其实已经进池了）。请先到控制台或「号池数据」里核对到期日，不要重复提交；'
            + '确实要再续一单，请等 10 分钟后再试。' };
        }
        const oldExp = String((keepRow && keepRow.exp) || '').slice(0, 10);
        const wasPub = Number(keepRow && keepRow.pub) === 1;      // 公益号（exp 也是 forever，必须靠 pub 区分）
        const newExp = renewExpCalc(oldExp, days, wasPub);
        // 「只有有效时长真的增加了才算续费」：没涨说明是重复提交（例如刚续过费又点一次），
        // 什么都不写，免得白记一笔台账、白给一次提成。
        // ⚠ 不能直接 `newExp <= oldExp` 比字符串：
        //   oldExp='forever' 时，'2026-12-10' <= 'forever' 成立（'2' < 'f'），
        //   公益号续费会被判成「没增加」直接拒掉。必须分情况。
        const _noGain = !oldExp ? false
          : (oldExp === 'forever' ? !wasPub                 // 真永久号：买什么都不再增加；公益号(forever+pub)要放行
            : (days === 0 ? false                           // 有期限 → 买永久套餐 = 升级，放行
              : (newExp <= oldExp)));
        if (_noGain) {
          return { ok: false, msg: '该账号已登记过，本次没有增加有效期（刚续过费？），无需重复登记。' };
        }
        entry.exp = newExp;
        if (keepRow && keepRow.added) entry.added = String(keepRow.added).slice(0, 19);   // 保留原入池日
        console.log('续费：' + String(entry.name || uidKey) + '  ' + (wasPub ? '公益号' : oldExp) +
                    ' → ' + newExp + '（+' + days + ' 天）');
      } else if (kind === 'fix') {
        // 补号：有效期继承原单，一分钱不收，不给提成
        entry.exp = String(keepRow.exp).slice(0, 10);
        if (keepRow.added) entry.added = String(keepRow.added).slice(0, 19);
        entry.rb = 1;
        entry.rb_start = String(keepRow.added || '').slice(0, 19);
        boughtDays = 0;                                           // 免费，本次买到 0 天
        console.log('补号（免费、继承原单）：' + String(entry.name || uidKey) + '  到期 ' + entry.exp);
      } else {
        boughtDays = planDaysOf(entry.exp);                       // 新登记：本次套餐天数
      }
      entry.__kind = kind;                                        // 给台账用，写库前删掉

      // 清掉「其它重复行」：同一个号可能同时按 uid / name 命中两条，
      // 保留 keepRow 那条（下面 upsert 原地更新），其余过期/公益的删掉，避免并存两份。
      if (dup.length) {
        for (const d of dup) {
          if (!d || (keepRow && String(d.uid) === String(keepRow.uid))) continue;
          try {
            if (d.uid != null && String(d.uid) !== '') {
              await d1Run('DELETE FROM accounts WHERE pool=? AND uid=?', [POOL_NAME, String(d.uid)]);
            }
          } catch (e) {}
        }
        // KV 侧：entry:u / entry:n 两种键都清一遍再重写
        for (const k of [ekey,
                         ...dup.map(d => (d && d.uid != null && String(d.uid) !== '') ? 'entry:u' + String(d.uid) : ''),
                         entry.name ? 'entry:n' + encodeURIComponent(String(entry.name)) : '']) {
          if (!k) continue;
          try { await POOL.delete(k); } catch (e) {}
        }
      }
      // KV 仍写一份：D1 万一回滚，KV 里必须是完整数据
      // 2026-11-10：KV 写必须容错 —— 免费额度只有 1000 写/天，写满后 POOL.put 直接抛异常。
      //   原来这一行没有 try/catch，KV 打满时「D1 明明写得进」却给买家报 500，
      //   买家重试又被判「已登记过」，等于卡死。D1 才是权威库，KV 写失败不该影响结果。
      // 类型标签只给台账用，不能写进账号数据（否则 KV 里多一个没人认识的字段）。
      const _regKind = String(entry.__kind || 'new');
      delete entry.__kind;
      let kvOk = true;
      try { await POOL.put(ekey, JSON.stringify(entry)); }
      catch (e) { kvOk = false; console.error('KV 写 entry 失败（继续走 D1）:', e && e.message); }
      if (!(await d1Upsert(entry))) {
        console.error('D1 登记镜像失败（KV ' + (kvOk ? '已写入' : '也写失败') + '）');
        /* 2026-11-10：D1 的 upsert 是「ON CONFLICT DO UPDATE」，冲突检查要读索引 ——
           D1 读额度打满（code 7500）时它跟着失败，而买家页面上已经显示「登记成功」，
           后台（读 D1）却查不到这个号。用 INSERT-only 的补偿表记下来，cron 重放补齐
           （INSERT 在额度打满时仍然可写，不消耗读）。 */
        if (kvOk) {
          try {
            await d1Run('INSERT OR IGNORE INTO acct_fixups (pool,uid,name,added,state,ctime) ' +
                        'VALUES (?,?,?,?,?,?)',
              [POOL_NAME, String(uidKey || ''), String(entry.name || ''),
               String(entry.added || ''), 'pending', bjStamp()]);
          } catch (e) {}
        } else {
          // KV 和 D1 都没写成：这时绝不能回「成功」，否则号彻底丢了
          return { ok: false, msg: '数据库暂时繁忙，登记没有完成（这次不占名额），请 3 分钟后再点一次' };
        }
      }
      // 2026-11-05：落一笔记账流水（成交台账）。写失败只告警 —— 记账出错不能反过来让登记失败。
      // 2026-11-10：带上类型。src: new=新登记 / renew=续费 / fix=补号（补号 rb=1，不计营收不计提成）。
      //   续费与补号的台账 day 必须写「今天」—— 台账唯一键是 (pool,uid,day)，写原入池日的话
      //   会把首单那一行覆盖掉，月度结算就再也看不到「这个月新开了多少单」。
      const _kind = _regKind;
      try {
        await ledgerAdd(entry, {
          src: _kind,
          rb: _kind === 'fix' ? 1 : 0,
          day: _kind === 'new' ? '' : beijingDate(),
          price: _kind === 'fix' ? 0 : undefined,
          remark: _kind === 'renew' ? '续费' : (_kind === 'fix' ? '补号（免费）' : ''),
        });
      } catch (e) { console.error('记账流水写入失败:', e && e.message); }
      // 重新登记 → 清墓碑（只影响 KV 回退路径）
      try {
        const deadLog = new Set(await getDeadLog());
        if (deadLog.size) {
          const cleared = [...deadLog].filter(k => k !== ekey
            && !(uidKey && k === 'entry:u' + uidKey)
            && !(entry.name && k === 'entry:n' + encodeURIComponent(String(entry.name))));
          if (cleared.length !== deadLog.size) await POOL.put('dead_log', JSON.stringify(cleared));
        }
      } catch (e) {}
      // 只有真要推 Secrets 时才做「全池 + 新号」合并（那是一次全表读）——
      // 默认关闭推送后，这里不该再为一份没人读的分片白跑一次查询。
      if (await pushPoolEnabled()) await pushPool(await mergePoolEntry(entry, ekey));
      try { await refreshPoolSnap(true); } catch (e) {}   // 新增/续费号：必须立刻进灾备快照
      // 2026-11-10：把类型与最终有效期回给调用方，页面/EXE 才能显示
      // 「续费成功，到期日 2026-12-10（在原基础上 +30 天）」而不是一律「登记成功」。
      const _k = String(kind || 'new');
      return { ok: true, kind: _k, exp: String(entry.exp || ''), added: String(entry.added || ''),
        days: boughtDays };
    }
  }

  // ---- KV 回退路径（D1 未绑定或查询失败）----
  // 2026-10-29：与 D1 路径同口径 —— 已过有效期的旧登记不算「已登记过」，允许覆盖。
  const kvOld = await POOL.get(ekey);
  if (kvOld) {
    let _old = {};
    try { _old = JSON.parse(kvOld) || {}; } catch (e) {}
    // 2026-11-09：公益号（到期降级留下的 pub=1 / exp=forever）必须允许重新登记 = 续费。
    // 只判 exp 的话 forever 不算过期，到期想续费的人会被永远挡住（与 D1 路径同一个坑）。
    // 2026-11-10：relogin=1（CK 已确认失效、等号主重登）同样放行 —— 与 D1 路径的 live/dead
    //   分离同口径，否则 D1 读额度被闸门拦下时，补登号又会被「已登记过」挡住。
    if (!_old.pub && !_old.relogin && !isExpiredExp(_old.exp)) {
      return { ok: false, msg: '该账号已登记过（每个账号限登记一首歌），无需重复登记。' };
    }
    try { await POOL.delete(ekey); } catch (e) {}
  }
  const deadLog = new Set(await getDeadLog());
  const master = await mergePool();
  const staleKeys = [];                        // 到期旧条目：允许被这次登记覆盖，稍后清掉
  for (const e of master) {
    if (deadLog.has(entryKeyOf(e))) continue;   // 墓碑内的是缓存残留（刚被清理），不算已登记
    const same = (uidKey && e.uid != null && String(e.uid) === uidKey)
      || (entry.name && e.name === entry.name);
    // 2026-11-09：pub=1 的公益号（到期降级）视同「旧登记」，允许覆盖 = 续费。
    if (same && (e.pub || isExpiredExp(e && e.exp))) { staleKeys.push(entryKeyOf(e)); continue; }
    if (uidKey && e.uid != null && String(e.uid) === uidKey) {
      return { ok: false, msg: '该账号已登记过（每个账号限登记一首歌），无需重复登记。' };
    }
    if (entry.name && e.name === entry.name) {
      return { ok: false, msg: '该手机号/账号已登记过（每个账号限登记一首歌），无需重复登记。' };
    }
  }
  for (const k of staleKeys) { try { await POOL.delete(k); } catch (e) {} }
  if (staleKeys.length) console.log('到期号重新登记（续费，KV 路径）:', String(entry.name || uidKey));
  // 权威写入：只写自己的独立键，永远不会覆盖别人的登记
  // 2026-11-10：这条分支的 KV 写是唯一权威（D1 读已经不可用），写失败必须如实报错，
  //   不能再像以前那样抛出去被外层吞成 500 —— 买家分不清「没写进去」和「服务器抽风」。
  try { await POOL.put(ekey, JSON.stringify(entry)); }
  catch (e) {
    console.error('KV 写 entry 失败（KV 兜底路径）:', e && e.message);
    return { ok: false, msg: '数据库暂时繁忙，登记没有完成（这次不占名额），请 3 分钟后再点一次' };
  }
  // D1 影子库同步（2026-10-22）：失败只记日志，绝不影响登记结果
  try {
    if (!(await d1Upsert(entry))) {
      await d1Run('INSERT OR IGNORE INTO acct_fixups (pool,uid,name,added,state,ctime) VALUES (?,?,?,?,?,?)',
        [POOL_NAME, String(uidKey || ''), String(entry.name || ''),
         String(entry.added || ''), 'pending', bjStamp()]);
    }
  } catch (e) { console.error('D1 镜像失败:', e && e.message); }
  // 2026-11-05：记账流水（与 D1 路径同口径）。D1 已经不可用时这里也会是 no-op。
  try { await ledgerAdd(entry); } catch (e) { console.error('记账流水写入失败:', e && e.message); }
  // 重新登记成功 → 清掉墓碑（dead_log 里移除本账号的 uid 键与 name 键两种形态）
  if (deadLog.size) {
    const cleared = [...deadLog].filter(k => k !== ekey
      && !(uidKey && k === 'entry:u' + uidKey)
      && !(entry.name && k === 'entry:n' + encodeURIComponent(String(entry.name))));
    if (cleared.length !== deadLog.size) {
      try { await POOL.put('dead_log', JSON.stringify(cleared)); } catch (e) {}
    }
  }
  // master 缓存尽力刷新（此写有竞态也无害：下次 mergePool 自愈）
  const updated = master.filter(e => staleKeys.indexOf(entryKeyOf(e)) < 0).concat([entry]);
  // master 缓存不再回写（2026-10-22）：读者全走 D1，entry: 独立键才是权威
  await pushPool(updated);
  // 本分支是「D1 查重失败」才走到：如果只是查询超时（D1 仍可写），这次快照能补上新号；
  // 真的未绑定时 refreshPoolSnap 自己会因 d1ok() 为假直接返回 false，不会抛错。
  try { await refreshPoolSnap(true); } catch (e) {}   // 新号 → force，跳过 30 分钟节流
  return { ok: true };
}

// ====================================================================
// D1 号池（2026-10-22 新增；KV 仍是唯一权威，D1 是影子库，双写 + 只读查询）
// 目的：
//   ① 让 run.py 直接问「我这一班该跑哪些号、每个号听哪几首」，彻底废掉
//      GitHub Secrets 分片（48KB 上限 / 槽位上限 500 / 半更新 三个问题一起消失）；
//   ② 每日轮转分配：听众集合每天 100% 更换，但每首歌每天恰好 p 个听众，一个都不漏。
// 约定：任何 D1 异常只 console.error，绝不抛出、绝不影响 KV 主流程。
// ====================================================================
const POOL_NAME = 'hz';        // 主群；dingzhi 版为 'dz'
const ASSIGN_TARGET = 30;      // 每首歌每天的目标听众数
// 跨群互听/控制台拉对端的默认地址（KV 里 PEER_URL 可覆盖）。
// 2026-10-23：dz.xx1031.xyz 已下线（该域名随旧邮件流到用户手里），定制版统一用 dingzhi.xx1031.xyz。
const PEER_DEFAULT = 'https://dingzhi.xx1031.xyz';

function d1ok() {
  try { return typeof DB !== 'undefined' && DB && typeof DB.prepare === 'function'; } catch (e) { return false; }
}
// 2026-11-05 晚：D1 最后一次报错的原因（只在单次 invocation 内有意义）。
// 起因：D1 免费额度（500 万行读/天）被月度结算的子查询打光后，所有带 WHERE 的写入都被
// 7500 拒绝，而接口仍然回「已修改」只附一句小字警告 —— 用户看到的就是「编辑功能坏了」。
// 现在把真实原因带到前端，并让写接口直接失败，不再假成功。
let _d1LastErr = '';
function d1ErrHint() {
  const m = String(_d1LastErr || '');
  if (/exceeded D1'?s? free tier/i.test(m)) return 'D1 今日免费额度已用尽（每天 500 万行读），北京时间次日 08:00 恢复';
  if (/readonly|read-only/i.test(m)) return 'D1 处于只读状态';
  if (m) return String(m).slice(0, 160);
  return '原因未知（D1 未返回错误信息）';
}
// ====================================================================
// 2026-10-25：歌曲/账号元数据自动补齐（控制台打开时后台补几条，慢慢补完）
// 用途：song_meta / acc_meta 是控制台「共创歌曲 / 绑错歌」标签的数据源，
//       新号登记后如果没人跑 tmp/sync_song_meta.py，这两张表就会缺数据（缺了只是不打标签，不会报错）。
// 策略：每次控制台加载顺手补 6 首歌 + 4 个号，全部 try/catch 静默失败，绝不阻塞、绝不影响页面。
async function backfillMeta(){
  if(!d1ok())return {skip:1};
  // 2026-11-06：15 分钟节流 —— 这是控制台首屏最大的一笔 D1 额度浪费。
  // 现状：本函数在「打开 /console 页面」和「/api/console/data」两处都被 waitUntil 调起，
  //   所以用户刷一次页面它跑两遍；开头两条查询都要扫全池
  //   （① accounts LEFT JOIN song_meta ≈ 704 行  ② accounts LEFT JOIN acc_meta ≈ 704+795 行），
  //   合计约 2,200 行/次 × 2 次 ≈ 4,400 行，而没有待补项时纯属空跑。
  // 影响：只影响「共创歌曲 / 绑错歌」两个标签的补齐时机，最多晚 15 分钟；
  //   那两列本来就是事后排查用的，晚一点不影响任何操作、不影响播放与快照。
  // 为什么是 15 分钟而不是更短：每次通过闸门要写一次时间戳。失败一律退化成「每次都跑」，不影响正确性。
  // 2026-11-10：时间戳从 KV 搬到 Cache API —— 它只是「上次跑过没」的书签，丢了最多多重跑一次，
  //   而 KV 写免费额度只有 1,000/天、实际是这套系统最紧的额度（11-09 已打满 100%）。
  //   15 分钟节流 = 原本 96 次/天 KV 写，现在 0。Cache API 每 colo 一份，多 colo 就多跑一次，无影响。
  try{
    const tick=Number(await caGet('meta:tick'))||0;
    if(tick&&Date.now()-tick<900000)return {skip:'throttle'};
    await caPut('meta:tick',String(Date.now()),900);
  }catch(e){}
  const now=new Date(Date.now()+8*3600*1000).toISOString().replace('T',' ').slice(0,19);
  // 这两个接口用桌面 Chrome UA 更稳（全局 UA 是 iPhone 版，登录接口在用，别动它）
  const MUA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
  const sleep=ms=>new Promise(r=>setTimeout(r,ms));
  const stat={songs:0,acc:0,empty:0,fail:0,err:'',at:now};
  // ① 没同步过的歌：批量调网易歌曲详情，拿作者列表（一次 12 首，1 个 subrequest 解决）
  try{
    const rows=await d1All("SELECT DISTINCT a.song AS song FROM accounts a WHERE a.song IS NOT NULL AND a.song<>'' AND NOT EXISTS (SELECT 1 FROM song_meta m WHERE m.song=a.song) LIMIT 12");
    const ids=(rows||[]).map(r=>String(r.song));
    if(ids.length){
      const r=await fetch(BASE+'/api/song/detail?ids=%5B'+ids.join(',')+'%5D',{headers:{'User-Agent':MUA,Referer:BASE+'/'}});
      const j=await r.json();
      const got=(j&&Array.isArray(j.songs))?j.songs:[];
      const st=[];
      for(const s of got){
        const arts=(s.artists||s.ar||[]).map(x=>[String(x.id),x.name||'']);
        st.push(DB.prepare('INSERT OR REPLACE INTO song_meta(song,name,dur,n_artists,artists,first_artist,gone,updated_at) VALUES (?,?,?,?,?,?,0,?)')
          .bind(String(s.id),s.name||'',Math.round((s.duration||s.dt||0)/1000),arts.length,JSON.stringify(arts),arts[0]?arts[0][1]:'',now));
        stat.songs++;
      }
      // 网易没返回的 = 已下架/删除，标 gone
      for(const id of ids){
        if(!got.some(s=>String(s.id)===id))
          st.push(DB.prepare('INSERT OR REPLACE INTO song_meta(song,name,dur,n_artists,artists,first_artist,gone,updated_at) VALUES (?,?,?,?,?,?,1,?)')
            .bind(id,'',0,0,'[]','',now));
      }
      if(st.length)await DB.batch(st);
    }
  }catch(e){ stat.err='song:'+((e&&e.message)||e); }
  // ② 没同步过音乐人身份的号：逐个查公开 user/detail（无需 CK）。
  //    注意两点：① acc_meta 里「上次失败」的 NULL 占位行也要算待补（NOT EXISTS 会漏，踩过）；
  //             ② 连发太快会被网易按「操作频繁 code=405」限流，每个请求之间必须留间隔。
  try{
    // 2026-11-11 补第三类待补：artist_id=''（确认非音乐人）但记录超过 7 天的也重检 ——
    //   有号 11-08 同步时还不是音乐人、11-11 已是（15123972125 实测）：号主后来入驻/转正，
    //   老的 '' 永远不刷新会让控制台把这种号错标成红「非音乐人」。7 天重检一次，20/15 分钟自动消化。
    const rows=await d1All("SELECT DISTINCT a.uid AS uid FROM accounts a LEFT JOIN acc_meta m ON m.uid=a.uid WHERE a.song IS NOT NULL AND a.song<>'' AND (m.uid IS NULL OR m.artist_id IS NULL OR (m.artist_id='' AND m.updated_at < datetime('now','-7 days'))) LIMIT 20");
    for(const row of (rows||[])){
      const uid=String(row.uid);
      await sleep(260);
      try{
        const r=await fetch(BASE+'/api/v1/user/detail/'+uid,{headers:{'User-Agent':MUA,Referer:BASE+'/'}});
        const j=await r.json();
        const p=(j&&j.profile)||null;
        if(!p){ stat.fail++; if(j&&j.code)stat.err='acc:'+j.code; continue; }
        await DB.prepare('INSERT OR REPLACE INTO acc_meta(uid,artist_id,artist_name,updated_at) VALUES (?,?,?,?)')
          .bind(uid,String(p.artistId||''),p.artistName||'',now).run();
        if(p.artistId)stat.acc++; else stat.empty++;
      }catch(e){ stat.fail++; stat.err='acc:'+((e&&e.message)||e); }
    }
  }catch(e){ stat.err='accouter:'+((e&&e.message)||e); }
  // 记一行执行结果，方便排查（D1 kv_misc 的 meta:last）
  try{ await DB.prepare('INSERT OR REPLACE INTO kv_misc(k,v,updated_at) VALUES (?,?,?)').bind('meta:last',JSON.stringify(stat),now).run(); }catch(e){}
  return stat;
}
async function d1All(sql, params) {
  if (!d1ok()) return null;
  try {
    const st = DB.prepare(sql);
    const r = params && params.length ? await st.bind(...params).all() : await st.all();
    return (r && r.results) || [];
  } catch (e) {
    _d1LastErr = String((e && e.message) || e);
    console.error('D1 all 失败:', e && e.message); return null;
  }
}

// 死号流水写 D1（2026-10-22 新增）：KV 里的 dead_log 只是「墓碑名单」，最多 500 条、只存键名，
// 看不出是谁、什么时候、因为什么被清理。D1 dead_log 表存完整流水，供周报统计与事后追查。
async function d1LogDead(entries, reason) {
  if (!d1ok() || !entries || !entries.length) return;
  const at = new Date(Date.now() + 8 * 3600 * 1000).toISOString().replace('T', ' ').slice(0, 19);
  for (const e of entries) {
    try {
      await d1Run('INSERT INTO dead_log (pool,uid,name,reason,at) VALUES (?,?,?,?,?)',
        [POOL_NAME,
         e && e.uid != null && String(e.uid) !== '' ? String(e.uid) : null,
         e && e.name ? String(e.name) : null,
         reason || 'unknown', at]);
    } catch (err) { console.error('D1 死号流水写入失败:', err && err.message); }
  }
}

// 北京时间时间戳（YYYY-MM-DD HH:MM:SS），dead_log / dead_notice 统一口径，字符串可比大小
function bjStamp(ms) {
  return new Date((ms != null ? ms : Date.now()) + 8 * 3600 * 1000).toISOString().replace('T', ' ').slice(0, 19);
}

// 手动删号的「是否通知号主」队列（2026-10-26 新增）。
// 背景：控制台删号在 worker 内部完成（applyEntryEdit），全程没有任何 Python 进程参与，
//       而 SMTP 只能从 GitHub Actions 侧发 → 之前 12 条手动删除一封邮件都没发出去。
// 口径：不无脑发，只对「真删」发（判定逻辑见 /api/dead_pending）。
// 没留邮箱的号也入队（判定时标 skip_noemail）—— 这样控制台每条手动删号都有明确状态，
// 不会出现「删了但不知道通没通知」的空白行。
async function d1QueueNotice(e, kind) {
  if (!d1ok() || !e) return false;
  return d1Run('INSERT OR IGNORE INTO dead_notice (pool,uid,name,email,removed_at,state,kind) VALUES (?,?,?,?,?,?,?)',
    [POOL_NAME, String(e.uid != null ? e.uid : ''), String(e.name || ''), String(e.email || '').trim(),
     bjStamp(), 'pending', String(kind || '')]);
}

// ====================================================================
// 号主邮件队列 mail_queue（2026-11-06 新增）：登记成功通知 + 到期提醒。
// 为什么还是一套「worker 排队 → Actions 派发」：SMTP 只能从 GitHub Actions 侧连（见 dead_notice）。
// 表结构（tmp/ddl_mail_queue.py 建）：唯一键 (pool,uid,kind,ref)。
//   kind  reg=登记成功 / exp30|exp15|exp7|exp3|exp1=到期提醒（剩余天数档位）
//   ref   去重基准：reg=登记日(added 日期) / exp=到期日(exp)
//         → 续费改了 exp / 重新登记换了 added，键就变了，老提醒自然作废、新一轮重新计时。
// 群号不入队：发送时（/api/mail_pending）按当时的 reg_cfg 现查，客服改群号立即生效。
// 任何写入失败都只记日志，绝不影响登记/播放主流程。
// ====================================================================
/* 2026-11-10 修复：这个数组**必须升序**。
   扫描处用的是 `MAIL_STAGES.find(s => left <= s)`（剩余天数 ≤ 档位），取的是「第一个够用的档位」。
   原来写成降序 [30,15,7,3,1]：剩 14 天时 14<=30 成立，直接命中 30 档 ——
   而唯一键 (pool,uid,kind,ref) 会挡掉重复入队，结果就是**每个号只在剩 30 天时收到 1 封，
   15/7/3/1 四档永远发不出来**（实测 mail_queue 里 exp30 有 47 条，其余四档 0 条）。
   改成升序后：剩 14 天→15 档、6 天→7 档、0~1 天→1 档。
   2026-11-10：用户决定砍成 3 封（15/7/1）。30 天和 3 天两档取消 ——
   30 天那封太早（客户记不住），3 天与 7 天太近（连发两封像催收）。
   回滚只要把这个数组改回 [1,3,7,15,30] 即可，notify_mail.py 按 kind 后缀解析天数，无需同步改。 */
const MAIL_STAGES = [1, 7, 15];
async function mailEnqueue(pool, uid, kind, ref, email, name, agent, exp) {
  if (!d1ok()) return false;
  // 2026-11-08：扫码/无手机号登记的占位名（qr: / manual: / name: 前缀）不该出现在邮件正文。
  // 邮件端 who = name or uid，原样传真会变成「qr:123456」。这里剥掉前缀，让 uid 兜底。
  name = String(name || '').replace(/^(?:qr|manual|name):[0-9A-Za-z_-]*$/i, '');
  return d1Run('INSERT OR IGNORE INTO mail_queue (pool,uid,kind,ref,email,name,agent,exp,state,created_at) ' +
    'VALUES (?,?,?,?,?,?,?,?,?,?)',
    [String(pool || ''), String(uid != null ? uid : ''), String(kind || ''), String(ref || ''),
     String(email || '').trim(), String(name || ''), String(agent || ''), String(exp || ''),
     'pending', bjStamp()]);
}

async function d1Run(sql, params) {
  if (!d1ok()) { if (!_d1LastErr) _d1LastErr = 'D1 未绑定（DB 为空）'; return false; }
  try {
    const st = DB.prepare(sql);
    if (params && params.length) await st.bind(...params).run(); else await st.run();
    return true;
  } catch (e) {
    _d1LastErr = String((e && e.message) || e);
    console.error('D1 run 失败:', e && e.message); return false;
  }
}
// 2026-11-06：同 d1Run，但返回「实际改动行数」。d1Run 只回布尔，而客服改名要把
// 「改了多少个号、多少笔订单」如实报给控制台，否则用户无法确认到底改没改到。
// 返回 -1 = D1 不可用 / 执行失败（调用方必须当成失败处理，绝不能当 0 行）。
async function d1Changes(sql, params) {
  if (!d1ok()) { if (!_d1LastErr) _d1LastErr = 'D1 未绑定（DB 为空）'; return -1; }
  try {
    const st = DB.prepare(sql);
    const r = (params && params.length) ? await st.bind(...params).run() : await st.run();
    return (r && r.meta && typeof r.meta.changes === 'number') ? r.meta.changes : 0;
  } catch (e) {
    _d1LastErr = String((e && e.message) || e);
    console.error('D1 changes 失败:', e && e.message); return -1;
  }
}
// 单条镜像（新增/修改后调用）。
// 2026-10-26 修复：无 uid 的历史条目以前直接 return false，导致这些号在控制台上的
// 「改歌 / 改邮箱 / 改有效期」只写进 KV，而读路径走 D1 → 刷新一次就变回旧值（假成功）。
// D1 里这类行的定位键是 'name:<name>' 占位（见 d1RowToEntry 的反向还原），这里按同一口径写。
// opt.keepEmpty === false → 这次是「控制台明确编辑」，允许把 note/rb/rb_start 写成空/0（清空）。
// 默认保持「非空才覆盖」：/api/d1_sync 之类从 KV 老数据回灌时，KV 里没有这几列，
// 无脑覆盖会把 640 个存量号的备注和补号标记一次清空（agent/plan 当年就是这么被清过的）。
async function d1Upsert(e, opt) {
  if (!d1ok() || !e) return false;
  const clearable = !!(opt && opt.keepEmpty === false);
  let uid = e.uid != null ? String(e.uid) : '';
  if (!uid) {
    if (!e.name) return false;
    uid = 'name:' + String(e.name);
  }
  const noteSet = clearable
    ? 'note=excluded.note'
    : 'note=CASE WHEN excluded.note<>\'\' THEN excluded.note ELSE accounts.note END';
  const rbSet = clearable
    ? 'rb=excluded.rb, rb_from=excluded.rb_from, rb_start=excluded.rb_start'
    : 'rb=CASE WHEN excluded.rb=1 THEN 1 ELSE COALESCE(accounts.rb,0) END, ' +
      'rb_from=CASE WHEN excluded.rb_from>0 THEN excluded.rb_from ELSE COALESCE(accounts.rb_from,0) END, ' +
      'rb_start=CASE WHEN excluded.rb_start<>\'\' THEN excluded.rb_start ELSE COALESCE(accounts.rb_start,\'\') END';
  return d1Run(
    'INSERT INTO accounts (pool,uid,name,song,ck,added,exp,no_listen,email,updated_at,agent,plan,pub,note,rb,rb_from,rb_start) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ' +
    'ON CONFLICT(pool,uid) DO UPDATE SET name=excluded.name, song=excluded.song, ck=excluded.ck, ' +
    'added=excluded.added, exp=excluded.exp, no_listen=excluded.no_listen, email=excluded.email, ' +
    'updated_at=excluded.updated_at, pub=excluded.pub, ' +
    // 2026-10-27：agent/plan 用「新值非空才覆盖」——/api/d1_sync 之类从 KV 老数据回灌时，
    // KV 里没有这两列，无脑覆盖会把 505 个存量号的客服归属一次清空。
    'agent=CASE WHEN excluded.agent<>\'\' THEN excluded.agent ELSE accounts.agent END, ' +
    'plan=CASE WHEN excluded.plan<>\'\' THEN excluded.plan ELSE accounts.plan END, ' +
    // 2026-11-05：备注/补号标记（按上面的 clearable 决定是否允许写空）
    noteSet + ', ' + rbSet + ', ' +
    // 2026-11-04：号主重新登记（CK 真变了）→ 清掉「已通知重登」标记，下一轮自动回到听众环。
    // 必须按 CK 变化判断而不是每次登记都清：/api/d1_sync 之类从 KV 老数据回灌时 CK 不变，
    // 无脑清空会让刚通知过的号立刻又回到听众环、再失败一次、再发一封邮件。
    'relogin_at=CASE WHEN accounts.ck<>excluded.ck THEN \'\' ELSE COALESCE(accounts.relogin_at,\'\') END',
    [POOL_NAME, uid, String(e.name || ''), String(e.song || ''), String(e.ck || ''), String(e.added || ''),
     // 2026-11-11：公益号（pub=1）一律写 'forever'。所有写入口（控制台编辑、/api/d1_sync 回灌、
     // pruneExpired 到期降级、补号重放）都走这一个漏斗，在这里归一化才能保证「库里不存在
     // 有到期日的公益号」这个不变量 —— 否则某条路径漏改，第二天到期号会被当成普通号再算一遍。
     e.pub ? 'forever' : String(e.exp || ''), e.noListen ? 1 : 0, String(e.email || ''), new Date().toISOString(),
     String(e.agent || ''), String(e.plan || ''), e.pub ? 1 : 0,
     String(e.note || ''), e.rb ? 1 : 0, Number(e.rbFrom) || 0, String(e.rbStart || '')]
  );
}
// 2026-11-10：登记补偿重放（配 acct_fixups 表，建表见 tmp/d1_acct_fixups_1110.py）。
// 为什么需要它：addEntry 的 D1 写入是 upsert（ON CONFLICT DO UPDATE），冲突检查要读索引，
//   D1 读额度打满（错误码 7500）时它会失败；而买家页面此时已经回了「登记成功」，
//   后台读 D1 却查不到号（用户反馈的原话：显示登记成功，号池里找不到号）。
//   INSERT 在额度打满时仍可执行，所以用只增的 acct_fixups 记账，等额度恢复后重放 upsert。
// 触发点：/api/assign、/api/pool_stat（播放轮每片开工必过）、邮件 cron（每小时）。
// 节流：同 isolate 5 分钟一次；表空时那条 SELECT 扫 0 行，成本≈0。
let _fxAt = 0;
async function replayFixups() {
  if (!d1ok()) return 0;
  if (Date.now() - _fxAt < 300000) return 0;
  _fxAt = Date.now();
  const rows = await d1All("SELECT pool,uid,name,added FROM acct_fixups WHERE state='pending' " +
                           'ORDER BY ctime LIMIT 20', []);
  if (!rows || !rows.length) return 0;      // null = 读失败，下轮再来
  let n = 0;
  for (const r of rows) {
    const uid = String(r.uid || '');
    const nm = String(r.name || '');
    const k = uid ? 'entry:u' + uid : (nm ? 'entry:n' + encodeURIComponent(nm) : '');
    if (!k) continue;
    let ent = null;
    try {
      const raw = await POOL.get(k);
      if (raw) ent = JSON.parse(raw);
    } catch (e) { continue; }                // KV 读失败：留着下次
    if (!ent) {
      /* KV 里也没有（KV 写当时也失败了，或已被删除）：转人工。保留行，控制台能看到。 */
      await d1Run("UPDATE acct_fixups SET state='orphan',done_at=? WHERE pool=? AND uid=? AND added=?",
        [bjStamp(), String(r.pool || ''), uid, String(r.added || '')]);
      console.error('补偿重放：KV 也找不到该号，转人工:', (nm || uid));
      continue;
    }
    if (await d1Upsert(ent)) {
      await d1Run("UPDATE acct_fixups SET state='done',done_at=? WHERE pool=? AND uid=? AND added=?",
        [bjStamp(), String(r.pool || ''), uid, String(r.added || '')]);
      n++;
      console.log('补偿重放成功:', (ent.name || uid));
    }
  }
  /* 补进来的号要立刻在控制台可见：ccBust 是 handle 内部函数，这里够不到，
     直接落版本号（与 ccBust 同一语义）。KV 写失败无所谓，控制台缓存 5 分钟也会过期。 */
  if (n) { try { await POOL.put('cc:ver', String(Date.now())); } catch (e) {} }
  return n;
}
// 2026-11-09 修复「D1 没删掉、KV 侧当删成功」：
// 旧实现走 d1Run，只要 SQL 不抛异常就 return true —— `DELETE ... WHERE pool=? AND uid=?`
// 命中 0 行（pool/uid 有偏差、D1 那行其实在别的群）同样回 true。上层按铁律 3 认为「D1 已删」，
// 接着删 KV 键 + 写墓碑，于是号还在 D1 天天正常跑，KV 里却永久消失（实测 7 个号中招）。
// 现在按 meta.changes 判：>0 才算删成功；=0 时再查一次把「本来就不存在」和「条件没匹配」分开。
async function d1Delete(e) {
  if (!d1ok() || !e) return false;
  const uid = e.uid != null ? String(e.uid) : '';
  let del, chk, params;
  if (uid) {
    del = 'DELETE FROM accounts WHERE pool=? AND uid=?';
    chk = 'SELECT 1 AS x FROM accounts WHERE pool=? AND uid=?';
    params = [POOL_NAME, uid];
  } else if (e.name) {
    del = 'DELETE FROM accounts WHERE pool=? AND name=?';
    chk = 'SELECT 1 AS x FROM accounts WHERE pool=? AND name=?';
    params = [POOL_NAME, String(e.name)];
  } else {
    return false;
  }
  const n = await d1Changes(del, params);
  if (n < 0) return false;          // D1 不可用/执行失败 → 判失败（铁律 3c：读失败≠读到空）
  if (n > 0) return true;           // 真删掉了
  // 0 行：① 这行本来就不在（已被删/从未入库）→ 清 KV 是对的；
  //       ② WHERE 没匹配上（pool/uid 有偏差）→ 绝不能清 KV，否则就是 11-09 那 7 个号的复现。
  const left = await d1All(chk, params);
  if (left === null) return false;  // 读失败 → 判失败，宁可留着 KV 也不误删
  return left.length === 0;
}

// ====================================================================
// 记账流水 ledger（2026-11-05 新增）
// 背景：客服按「登记单数」单独拿提成，但掉线的客户要免费补一个号（补号不给提成）；
//       结算是次月 15 号回头算上月，所以必须有一份【不会随删号/改套餐漂移】的成交台账。
//       accounts 是「当前状态」——删号整行消失、改套餐原地覆盖，拿它算历史月账会凭空少单。
// 语义：
//   day      成交日（= 登记日 added 的日期部分），结算按这个月分组
//   start    服务开始日（补号时继承原单的 start）
//   exp      到期日（补号时继承原单的 exp，不重置）
//   price    单价（元）；NULL = 该档位没定价 → 结算页单列「待补价」，绝不当 0 元混进合计
//   rb       1 = 补号（免费补偿）：不计营收、不计提成，明细里单独一块
//   rb_from  关联的原单 ledger.id
//   src      reg=登记时自动记 / backfill=历史回填 / manual=人工补录
// 唯一键 (pool,uid,day)：同一个号同一天只留一笔，重复登记走更新不新增。
// ====================================================================
function ledgerUidOf(e) {
  const u = (e && e.uid != null && String(e.uid) !== '') ? String(e.uid) : ('name:' + String((e && e.name) || ''));
  return (u === 'name:' || !u) ? '' : u;
}
// 写一笔成交流水。任何异常都吞掉（记账失败绝不能让登记失败）。
async function ledgerAdd(e, opt) {
  if (!d1ok() || !e) return false;
  const o = opt || {};
  const uid = ledgerUidOf(e);
  if (!uid) return false;
  let price = -1;
  let days = 0;
  try {
    const rc = await regCfg();
    price = planPrice(rc, e.plan);
    const pl = (rc.plans || []).find(it => it.key === e.plan || it.label === e.plan);
    days = pl ? (Number(pl.days) || 0) : 0;
  } catch (_e) { price = -1; }
  const added = String(e.added || '') || beijingDateTime();
  // 2026-11-10：续费/补号要单独指定 day（= 今天）。台账唯一键是 (pool,uid,day)，
  // 续费时 added 保留原入池日，如果 day 也跟着用原入池日，就会把首单那行覆盖掉。
  const day = String(o.day || '').slice(0, 10) || added.slice(0, 10) || beijingDate();
  // 补号是免费的：price 明确给 0 时不能被套餐价盖回去（否则下个月又被算一次营收）。
  const finalPrice = (o.price !== undefined && o.price !== null)
    ? (Number(o.price) >= 0 ? Number(o.price) : null)
    : (price >= 0 ? price : null);
  const exp = String(e.exp || '') || 'forever';
  const src = String(o.src || 'reg');
  const at = beijingDateTime();
  const row = [POOL_NAME, uid, String(e.name || ''), String(e.agent || ''), String(e.plan || ''),
               finalPrice, days, day, String(o.start || day), exp,
               o.rb ? 1 : 0, Number(o.rbFrom) || 0, String(o.remark || ''), src, at];
  /* 2026-11-10 修复「同一天两笔互相覆盖」：
     唯一键原来是 (pool,uid,day)，且一律 ON CONFLICT(pool,uid,day) DO UPDATE —— 同一个号
     同一天出现两笔不同性质的单（新登记当天又续费 / 一天续两次）时，后一笔把前一笔覆盖掉：
     price 被改写、而 days 和 src 在 DO UPDATE 里压根没列出来 ⇒ 营收少一笔、套餐天数错乱、
     类型还留着旧的 'new'。现在分三步：
       ① 先按「同号 + 同日 + 同类型」查一笔 → 有则累加（一天续两次：钱和天数都保留）
       ② 没有则 INSERT 新行
       ③ 读失败、或 INSERT 撞上唯一索引 → 退回旧 UPSERT，宁可合并成一行也不丢这笔钱
     ⚠️ 唯一索引目前仍是 (pool,uid,day)，所以「同一天跨类型」（新登记 + 当天又续费）
        那一笔会撞索引、落到 ③ 合并成一行：金额和天数累加都对，只有 src 记成第一笔。
        这是**有意保留**的（2026-11-10 评估后决定不改索引）：D1 netpool 与 dz 共用，
        dz 既没有续费体系、也没有「时长没增加就拒绝」的 noGain 防线，
        一旦把索引改成 (pool,uid,day,src)，dz 那边同一笔重复提交会从「覆盖」变成「天数累加」= 虚增。
        真要改索引，必须先给 dz 补 noGain 防线。
        详见 文档\补登判定与台账同日多笔-修复说明-20261110.md */
  let hit = null;
  try {
    hit = await d1All('SELECT id FROM ledger WHERE pool=? AND uid=? AND day=? AND src=? LIMIT 1',
                      [POOL_NAME, uid, day, src]);
  } catch (_e) { hit = null; }
  if (hit && hit.length) {
    // 同类型同日已有 → 累加：price 相加（NULL = 待补价，NULL+n 仍是 NULL）、days 相加，
    // 到期日/套餐/备注取后一笔。rb 沿用「原来标了补号就不洗掉」的旧口径。
    return d1Run(
      'UPDATE ledger SET name=?, agent=?, plan=?, price=price+?, days=days+?, exp=?, at=?, ' +
      'rb=CASE WHEN rb=1 THEN 1 ELSE ? END, ' +
      'rb_from=CASE WHEN rb=1 THEN rb_from ELSE ? END, ' +
      'remark=CASE WHEN ?<>\'\' THEN ? ELSE remark END WHERE id=?',
      [String(e.name || ''), String(e.agent || ''), String(e.plan || ''), finalPrice, days, exp, at,
       o.rb ? 1 : 0, Number(o.rbFrom) || 0, String(o.remark || ''), String(o.remark || ''), Number(hit[0].id)]
    );
  }
  if (hit) {
    const okIns = await d1Run(
      'INSERT INTO ledger (pool,uid,name,agent,plan,price,days,day,start,exp,rb,rb_from,remark,src,at) ' +
      'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', row);
    if (okIns) return true;
  }
  // 已标记补号的那笔不能被「重新登记/回灌」洗回正常单 —— 否则免费补号下个月又被算一次提成
  return d1Run(
    'INSERT INTO ledger (pool,uid,name,agent,plan,price,days,day,start,exp,rb,rb_from,remark,src,at) ' +
    'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ' +
    'ON CONFLICT(pool,uid,day) DO UPDATE SET name=excluded.name, agent=excluded.agent, ' +
    'plan=excluded.plan, price=ledger.price+excluded.price, days=ledger.days+excluded.days, ' +
    'exp=excluded.exp, at=excluded.at, ' +
    'rb=CASE WHEN ledger.rb=1 THEN 1 ELSE excluded.rb END, ' +
    'rb_from=CASE WHEN ledger.rb=1 THEN ledger.rb_from ELSE excluded.rb_from END, ' +
    'remark=CASE WHEN excluded.remark<>\'\' THEN excluded.remark ELSE ledger.remark END',
    row
  );
}
// 把某个号的成交记录打上/去掉「补号」标记（控制台编辑弹窗调用）。
// 只动这个号【最近一笔】流水，老月份已经结过账的记录绝不回改。
async function ledgerMarkRebind(pool, uid, name, on, rbFrom, rbStart, remark, newExp, fallbackEntry) {
  if (!d1ok()) return false;
  const p = String(pool || POOL_NAME);
  const idQ = uid
    ? await d1All('SELECT id,day,price FROM ledger WHERE pool=? AND uid=? ORDER BY day DESC, id DESC LIMIT 1', [p, String(uid)])
    : await d1All('SELECT id,day,price FROM ledger WHERE pool=? AND name=? ORDER BY day DESC, id DESC LIMIT 1', [p, String(name || '')]);
  // 2026-11-06：读失败（null）与「账本里确实没有这笔」必须分开 —— 原来两者都进下面这个分支，
  // 读失败时 on=true 会凭空补写一笔流水 ⇒ 账本重复计单，金额直接算错，而且事后极难发现。
  if (idQ === null) {
    console.error('[ledger] 查「最近一笔流水」失败，本次不改账本');
    return false;
  }
  if (!idQ.length) {
    // 账本里还没有这个号（例如历史回填没覆盖到的老号）→ 直接补写一笔，别让「补号」标记凭空丢掉。
    if (on && fallbackEntry) {
      return ledgerAdd(fallbackEntry, { rb: 1, rbFrom: rbFrom, start: rbStart || '', remark: remark || '' });
    }
    return false;
  }
  const id = idQ[0].id;
  // 注意：ledger 没有 rb_start 列 —— 补号时继承后的「服务开始日」直接写进 start。
  // start / exp 只在有值时才更新：取消补号标记（on=false）时不该把已记录的日期抹掉。
  /* 2026-11-10：取消补号标记时，把「补号写死的 0 元」还原成 NULL（= 待补价）。
     原来取消后 rb=0 但 price 仍是 0，月度结算里这一单变成「正常单 0 元」——
     既不算营收、也不进「待补价」清单，等于这笔钱凭空消失，客服提成也跟着是 0。
     改成 NULL 后它会出现在「待补价」里，点一下就按当前套餐价补齐。
     ⚠ 只在「原本就是补号(rb=1)且价格是 0」的行上动手：正常成交单 price 有值，
       不受影响；只改备注时也会走这个函数（on=false），不能把正常单的价格抹掉。 */
  const sets = ['rb=?', 'rb_from=?', 'remark=?',
                'price=CASE WHEN rb=1 AND price=0 THEN NULL ELSE price END'];
  const params = [on ? 1 : 0, Number(rbFrom) || 0, String(remark || '')];
  if (rbStart) { sets.push('start=?'); params.push(String(rbStart)); }
  if (newExp) { sets.push('exp=?'); params.push(String(newExp)); }
  params.push(id);
  return d1Run('UPDATE ledger SET ' + sets.join(', ') + ' WHERE id=?', params);
}

// ====================================================================
// D1 读路径（2026-10-22 第二批：读也切到 D1）
// 背景：KV 的 mergePool 要 list 一次 + 把每个 entry 键读一遍（213 次读），
// 这是「日读 3.6 万」和「p50 CPU 9ms」的主要来源。D1 一条 SELECT 就够。
// 设计原则：D1 只做读，写仍然「KV 权威 + D1 镜像」不变；D1 任何异常都回退 KV，
// 所以即使 D1 挂了，登记/控制台/分配也不会停，只是慢回旧路。
// ====================================================================
// 2026-11-05：加 note（备注，复用库里已有的 note 列）/ rb（补号标记）/ rb_from（关联原单）/
// rb_start（原单登记日）。缺这几个的话控制台改完备注一刷新就变回空。
const D1_COLS = 'uid,name,song,ck,added,exp,no_listen,email,agent,plan,pub,note,rb,rb_from,rb_start';

// ---- 2026-11-08 省额度：全池读的排序从 SQL 挪到 JS ----
// D1 的 rows_read 把 `USE TEMP B-TREE FOR ORDER BY` 的代价也算进「读行数」：
// 657 行的全池读，带 ORDER BY（实测）1,314 行，不带（实测）657 行 —— 差了整整一倍。
// 排序结果用 657 行真实数据逐行比对过：`ORDER BY added, uid` 与下面这个比较器
// 得到的序列**完全相同**（added 是 'YYYY-MM-DD HH:MM:SS'，uid 是纯数字串，全是 ASCII，
// SQLite 的 BINARY 排序与 JS 字符串比较逐字节等价；NULL 两边都排最前）。所以显示顺序不变。
function d1PoolCmp(a, b) {
  const x = String(a && a.added != null ? a.added : '');
  const y = String(b && b.added != null ? b.added : '');
  if (x !== y) return x < y ? -1 : 1;
  const u = String(a && a.uid != null ? a.uid : '');
  const v = String(b && b.uid != null ? b.uid : '');
  return u < v ? -1 : (u > v ? 1 : 0);
}

// ---- 2026-11-08 省额度：登记查重不再用 OR ----
// 原来一条 `pool=? AND (uid=? OR name=?)` 里的 OR 让索引完全失效（实测扫 623 行，
// 约等于整个号池）。拆成两条单条件查询后各走各的索引：
//   · uid  → PRIMARY KEY (pool,uid) 覆盖索引 → 1 行（实测 1）
//   · name → idx_accounts_name(pool,name) → 0~1 行（实测 0）
// 两条都查、不「命中第一条就停」，顺带修掉一个隐患：以前 uid 命中一个**已过期**的旧行、
// name 命中另一个**仍有效**的号时，结果取决于扫到哪条 —— 现在两条都看得到，
// 只要有一条有效就拒绝（与 KV 回退路径的口径一致）。
// 返回：命中行数组（可能为空）；任一查询失败返回 null（= 查不了，交给上层回退 KV，绝不当作"没查到"）
async function d1FindDup(uidKey, name) {
  // 2026-11-09：额度闸门。返回 null = 查不了 → addEntry 走 KV 回退查重（那里是精确的 entry: 键，不是近似）。
  if (await d1ReadBlocked()) { console.log('D1 读额度 ≥' + QGATE_HOT + '%，查重改走 KV'); return null; }
  const nm = String(name || '');
  const qs = [];
  // 2026-11-09：带 pub —— 到期号被 pruneExpired 改成 pub=1/exp='forever'，
  // 'forever' 不算过期，只看 exp 会把「到期降公益号」判成「已登记过」，买家永远续不上费。
  // 2026-11-10：带 added —— 续费/补号要保留原「入池日」（否则首周加速被重置、白烧一周播放量）。
  // 2026-11-10：带 relogin_at —— CK 已确认失效、已通知号主重登的号仍留在 accounts 里等
  // RELOGIN_TTL_DAYS（默认 7 天）超时清理，buildPlanFrom 会把它摘出听众环，**其实并不参与播放**。
  // 不查这一列，这种号会被 addEntry 判成「还在池里正常运行」→ 客户拿补登链接来重登被拒，
  // 且提示恰好说反（详见 addEntry 里 live/dead 分离处）。
  if (uidKey) qs.push(d1All('SELECT uid,exp,pub,added,agent,plan,relogin_at FROM accounts WHERE pool=? AND uid=? LIMIT 1', [POOL_NAME, uidKey]));
  if (nm) qs.push(d1All('SELECT uid,exp,pub,added,agent,plan,relogin_at FROM accounts WHERE pool=? AND name=? LIMIT 1', [POOL_NAME, nm]));
  if (!qs.length) return [];
  const rs = await Promise.all(qs);
  const out = [];
  for (const r of rs) {
    if (r === null) return null;
    for (const x of r) out.push(x);
  }
  return out;
}

// D1 行 → KV entry 结构（保持字段名完全一致，上层代码无需改动）
// ====================================================================
// 2026-11-09：删号前复核整段删除了（原来有两版）——
//   ① neteaseUserAlive（2026-11-03）：用别的活号查 /api/v1/user/detail/<uid>，
//      code=200 就认为「账号还在，不能删」。它证明不了「这个 CK 还能用」，
//      于是「CK 死了、账号还在」（换设备/被顶号，最常见）被无限保留（11-09 清 6 个挂 5 天）。
//   ② ckAlive（2026-11-09 当日试验）：用号自己的 CK 调明文 /api/nuser/account/get。
//      实测不可用 —— 对池内随机 6 个健康号全部回 {code:200,account:null}，
//      而当天 dead_log 只删了 8 个 ⇒ 该判据在没有播放环境的出口 IP 上没有区分度。
// 结论：确认动作交给客户端（run.py.login_by_cookie：weapi account/get + v1 每日推荐双证据，
//   3 次里 2 次明确失效才判死），服务端收到 confirm=true 直接删 + 立刻直邮发信。
// 不要在这里重新引入任何「服务端再验一次 CK」的逻辑 —— 已验证不可靠。

function d1RowToEntry(r) {
  const uidRaw = String(r.uid || '');
  // 无 uid 的历史条目在库里用 'name:xxx' 占位（导入时补的），这里还原成「无 uid」
  const e = {
    name: String(r.name || ''),
    song: String(r.song || ''),
    ck: String(r.ck || ''),
    added: String(r.added || ''),
    exp: String(r.exp || ''),
    email: String(r.email || ''),
    // 2026-10-27：客服标签 + 套餐档位。存量行 ALTER 时清一色刷成「徐」/空（空=未标注）。
    agent: String(r.agent || ''),
    plan: String(r.plan || ''),
  };
  // 2026-11-05：备注（D1 列名 note）+ 补号标记。空值不写进 entry，保持 KV 条目干净。
  if (r.note) e.note = String(r.note);
  if (r.rb) e.rb = 1;
  if (r.rb_from) e.rbFrom = Number(r.rb_from) || 0;
  if (r.rb_start) e.rbStart = String(r.rb_start);
  if (uidRaw && !uidRaw.startsWith('name:')) e.uid = r.uid;
  if (r.no_listen) e.noListen = 1;
  // 2026-11-01：公益号（只帮别人听、自己的歌不进互听环、不签到）。列缺失/老库读不到时按 0 处理。
  if (r.pub) e.pub = 1;
  return e;
}

// 返回 null = D1 不可用/查询失败/表为空（调用方回退 KV）；返回数组 = 正常
async function d1Pool() {
  if (!d1ok()) return null;
  // 2026-11-09：额度闸门 —— ≥95% 时主动让路，返回 null 让 mergePool 用 KV 快照（682 行不烧了）。
  if (await d1ReadBlocked()) return null;
  // 2026-11-08：ORDER BY 去掉（改 JS 排，见 d1PoolCmp），每次全池读省一半读行数。
  const rows = await d1All('SELECT ' + D1_COLS + ' FROM accounts WHERE pool=?', [POOL_NAME]);
  if (!rows) return null;
  if (!rows.length) {
    // 空表几乎不可能（号池最少几十个号），当作异常处理，避免把「库被清空」误当成「号池为空」
    console.error('D1 号池为空，回退 KV 读取');
    return null;
  }
  rows.sort(d1PoolCmp);
  return rows.map(d1RowToEntry);
}

// 快照写入：一次 batch 写完整片（原来是 POOL.put 一个 snap: 键）。
// 好处：控制台回看可以直接 SELECT，不用先 list 再逐个 get；也不再占用 KV 的 list 配额。
async function d1SnapWrite(day, pool, clean) {
  if (!d1ok()) return false;
  const uids = Object.keys(clean || {});
  if (!uids.length) return true;
  try {
    const now = new Date().toISOString();
    // 2026-10-24 修复：D1 单次 batch 最多 1000 条语句，而 snap650 是 jobs=1 写全池。
    // hz 登记上限 1200，号池涨到千级后会整批写入失败（快照一条都进不去）。
    // 与 d1DursWrite/d1RunsWrite 统一按 100 条分批；小批量仍只跑一次循环，行为不变。
    for (let i = 0; i < uids.length; i += 100) {
      const stmts = uids.slice(i, i + 100).map(uid => DB.prepare(
        'INSERT INTO snapshots (day,pool,uid,rate,rpc30,cnt,missions,dur,at) VALUES (?,?,?,?,?,?,?,?,?) ' +
        // 2026-10-23：dur 用 COALESCE —— 时长老早就由 run.py 在播放时写入，而 10:00 的补采任务
        // 只关心 650 指标、手里没有时长，直接覆盖会把「时长」列清空。rate/rpc30/missions
        // 必须原样覆盖（那正是补采的目的：用结算后的值替换凌晨的旧值）。
        'ON CONFLICT(day,pool,uid) DO UPDATE SET rate=excluded.rate, rpc30=excluded.rpc30, ' +
        'cnt=COALESCE(excluded.cnt, snapshots.cnt), missions=excluded.missions, ' +
        'dur=COALESCE(excluded.dur, snapshots.dur), at=excluded.at ' +
        // 2026-11-09：真正实现「rpc30 大者胜」。原来是无条件 DO UPDATE = 最后写入者胜，
        // 而读侧的 prev 因主键 (day,pool,uid) 永远是单行、prev 恒为空，那段比较是死代码。
        // 于是任何晚到的旧值（早班补采、被取消的片重试）都能把已结算好的数据静默改小。
        // COALESCE 兜住没有 650 数据的号：NULL 比较结果为 NULL 会直接跳过写入，等于永远写不进去。
        'WHERE COALESCE(excluded.rpc30, -1) >= COALESCE(snapshots.rpc30, -1)'
      ).bind(day, pool, String(uid), clean[uid].rate, clean[uid].rpc30, clean[uid].cnt,
             JSON.stringify(clean[uid].mis || {}), clean[uid].dur, now));
      await DB.batch(stmts);
    }
    return true;
  } catch (e) { console.error('D1 快照写入失败:', e && e.message); return false; }
}

// ====================================================================
// 2026-11-05：快照只保留最近 90 天（每天由主 cron 顺手清一次）。
// 为什么要有：snapshots 是「每号每天一行」的体检记录，只增不减 ——
//   号池 700 个 × 每天 1 行 × 152 字节 ≈ 100KB/天 ≈ 36MB/年；
//   现在虽只占几 MB，但它是唯一会随时间线性膨胀的表（accounts / ledger 都跟着号数走，不跟天数走）。
// 为什么是 90 天：控制台真正读的只有「当天」和「最近 7 天」（今进度 / 连续不涨天数），
//   90 天留足三个月的回溯余量，同时把库体积钉在一个常量上。
// 为什么放在 cron 而不是备份脚本：备份是 GitHub Actions，worker 是 CF 原生 cron，
//   后者不依赖 Actions 配额、也不会因为 relay 改时间段而漂移。
// 一次删一天的量（~660 行），远低于 D1 单 SQL/batch 上限，不需要分批。
const SNAP_KEEP_DAYS = 90;
async function purgeOldSnapshots() {
  if (!d1ok()) return { skip: 1 };
  const cutoff = dateMinusN(beijingDate(), SNAP_KEEP_DAYS);
  const rows = await d1All('SELECT COUNT(*) n, MIN(day) d0 FROM snapshots WHERE day<?', [cutoff]);
  const n = rows && rows[0] ? (Number(rows[0].n) || 0) : 0;
  if (!n) return { deleted: 0, cutoff: cutoff };
  const ok = await d1Run('DELETE FROM snapshots WHERE day<?', [cutoff]);
  if (!ok) return { deleted: 0, cutoff: cutoff, failed: 1 };
  return { deleted: n, cutoff: cutoff, oldestWas: String((rows[0] && rows[0].d0) || '') };
}

// 时长沉淀（2026-10-22 新增 D1 主存储）：原来只有一个 KV 键 console:durs，
// 250 个分片并发做「读→改→写」，必然互相覆盖（丢更新）。D1 按 (pool,uid) UPSERT 天然无竞态。
async function d1DursWrite(pool, incoming) {
  if (!d1ok()) return 0;
  const uids = Object.keys(incoming || {});
  if (!uids.length) return 0;
  try {
    const now = new Date().toISOString();
    for (let i = 0; i < uids.length; i += 100) {
      const batch = uids.slice(i, i + 100).map(uid => DB.prepare(
        'INSERT INTO durs (pool,uid,dur,updated_at) VALUES (?,?,?,?) ' +
        'ON CONFLICT(pool,uid) DO UPDATE SET dur=excluded.dur, updated_at=excluded.updated_at'
      ).bind(pool, String(uid), Number(incoming[uid]) || 0, now));
      await DB.batch(batch);
    }
    return uids.length;
  } catch (e) { console.error('D1 时长写入失败:', e && e.message); return 0; }
}

// 实跑名单（2026-10-22 新增）：记录「这一天这一片真正跑完播放的号」，
// 供 /api/coverage 核对「应跑 vs 实跑」，补上以前「整片静默丢失但 job 仍然绿」的盲区。
async function d1RunsWrite(day, pool, uids, slice) {
  if (!d1ok()) return 0;
  if (!uids || !uids.length) return 0;
  try {
    const now = new Date().toISOString();
    for (let i = 0; i < uids.length; i += 100) {
      const batch = uids.slice(i, i + 100).map(uid => DB.prepare(
        'INSERT INTO runs (day,pool,uid,slice,at) VALUES (?,?,?,?,?) ' +
        'ON CONFLICT(day,pool,uid) DO UPDATE SET slice=excluded.slice, at=excluded.at'
      ).bind(day, pool, String(uid), String(slice || ''), now));
      await DB.batch(batch);
    }
    return uids.length;
  } catch (e) { console.error('D1 实跑名单写入失败:', e && e.message); return 0; }
}

// 计数型限流（2026-10-22 第三批）：D1 原子自增，返回自增后的计数。
// 为什么不用 KV：KV 是「读一次、加一、写回」，两个并发请求会读到同一个旧值 → 各写回 n+1，
// 等于少算一次，频控直接被绕过；而且 KV 免费额度写只有 1000 次/天。
// 语义：先自增再判断，超限的请求也计一次（宁可多算，不漏）。
// 返回 null = D1 不可用／写入失败，调用方必须回退 KV，不能让频控失效。
async function d1Hit(kind, key) {
  if (!d1ok()) return null;
  const k2 = kind + ':' + key;
  const ok = await d1Run(
    'INSERT INTO rate_limit (k,n,at) VALUES (?,1,?) ON CONFLICT(k) DO UPDATE SET n=n+1, at=excluded.at',
    [k2, new Date().toISOString()]);
  if (!ok) return null;
  const rows = await d1All('SELECT n FROM rate_limit WHERE k=?', [k2]);
  if (!rows || !rows.length) return null;
  return Number(rows[0].n) || 0;
}

// ---- 单键号池快照（2026-10-22 第三批）----
// 背景：mergePoolKV 原来是「list 一次 + 每个 entry 键 get 一次」。1200 个号 = 1201 次外部操作，
// 而单个 invocation 最多只能做 1000 次外部操作（Cloudflare 硬限）→ D1 一挂，KV 兜底路径
// 自己也必然失败，等于「灾备是假的」。
// 做法：维护一个 pool:<池> 单键（全池 JSON），兜底时 1 次读就拿到全池。
// 它不承担权威职责（entry: 键才是），只是为了「D1 不可用时这一轮还能跑起来」，偶尔落后无妨。
const poolSnapKey = () => 'pool:' + POOL_NAME;

// ====================================================================
// 2026-11-10：Cache API 小工具（不占 KV 额度）
// 背景：KV 免费额度只有 1000 写/天，而「控制台首屏缓存」和「Actions 状态缓存」
//   都是短 TTL、按访问触发写入 —— 控制台开着的时候一天就能刷掉几百上千次，
//   11-09 实测 KV 写被打到 100.0%（1000/1000），导致 entry 镜像、pool:hz 快照、
//   dev: 设备镜像全部写不进去。这些纯缓存搬进 Cache API 后 KV 写瞬间降下来，
//   而且 Cache API 不计入 KV 的任何额度。
// 语义差异：Cache API 是「每个数据中心各存一份」，不像 KV 全球一致 ——
//   对缓存来说完全够用（同一台机器反复刷新都落在同一个 colo）。
// 任何异常都退化成「不缓存」，绝不影响主流程。
// ====================================================================
const _CA_HOST = 'https://ca-cache.xx1031.xyz/';
let _caLastErr = '';   // 2026-11-10：Cache API 最近一次写失败的原因（只在单次 invocation 内有意义，供响应头排障）
let _caPutOk = 0, _caPutN = 0;   // 本次 invocation 内 caPut 的成功/总次数（排障用：看是不是被 subrequest 上限打掉）
function _caObj() { try { return (typeof caches !== 'undefined' && caches.default) ? caches.default : null; } catch (e) { return null; } }
function _caReq(k) { return new Request(_CA_HOST + encodeURIComponent(String(k)), { method: 'GET' }); }
async function caGet(k) {
  const c = _caObj();
  if (!c) return null;
  try { const r = await c.match(_caReq(k)); return r ? await r.text() : null; } catch (e) { return null; }
}
async function caPut(k, body, ttl) {
  const c = _caObj();
  _caPutN++;
  if (!c) { _caLastErr = 'no-caches-api'; return false; }
  try {
    await c.put(_caReq(k), new Response(body, {
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'max-age=' + (Number(ttl) || 300) } }));
    _caLastErr = '';
    _caPutOk++;
    return true;
  } catch (e) { _caLastErr = String((e && e.message) || e).slice(0, 120); return false; }
}

// ====================================================================
// 2026-11-09：D1 读额度闸门（用户口径：自主登记优先吃 D1，≥95% 才退 KV）
// 背景：D1 免费 500 万行读/天（UTC 日）。11-08 事故把额度打满后所有 SELECT 回 7500，
//   登记全链路只能靠 KV 镜像活着 —— 而那时 KV 也已经写穿，等于两条腿同时断。
// 做法：scheduled 每 30 分钟用 CF GraphQL 探一次当日 rows_read，写 KV `qgt:d1`
//   （{p: 百分比, t: 探测时间}）。读路径取这个水位：
//   p ≥ 95 且数据新鲜（≤90 分钟）→ 主动跳过一次 D1 读，先走 KV；
//   未知 / 过期 / 未配 token → 一律按现状走 D1（闸门自己坏掉不能影响功能）。
// 只拦「读」：D1 写额度 10 万行/天，单日业务量 <1000，写永远不跳。
const D1_READ_LIMIT = 5000000;
const QGATE_KEY = 'qgt:d1';
const QGATE_HOT = 95;            // ≥95% 视为「该让路」
let _qgPct = -2, _qgAt = 0;      // -2 = 本次 invocation 还没读过
async function d1QuotaPct() {
  if (_qgPct !== -2 && Date.now() - _qgAt < 60000) return _qgPct;
  let p = -1, t = 0;
  try {
    /* 2026-11-10：优先读 Cache API（自动探针写这里，不占 KV 写额度），
       读不到再退 KV（兼容手动 /api/quota_report 落的全局值和上线前的旧值）。 */
    let raw = await caGet(QGATE_KEY);
    if (!raw) raw = await POOL.get(QGATE_KEY).catch(() => null);
    if (raw) { const o = JSON.parse(raw) || {}; p = Number(o.p); t = Number(o.t) || 0; }
  } catch (e) {}
  if (!(p >= 0) || Date.now() - t > 5400000) p = -1;     // 90 分钟没更新 → 当未知，走 D1
  _qgPct = p; _qgAt = Date.now();
  return p;
}
async function d1ReadBlocked() { return (await d1QuotaPct()) >= QGATE_HOT; }

// GraphQL 探针（scheduled / /api/assign 里调；需要 KV 里配 CFQ_TOKEN + CFQ_ACCOUNT）
// force=true 跳过节流（手动 /api/quota_report 用）。
async function d1QuotaProbe(force) {
  if (!d1ok()) return { skip: 'no_d1' };
  let tok = '', acc = '', last = 0;
  try {
    // 优先 Worker Secret（env，加密存储、读不回），KV 只作为手动备用。
    tok = cleanKV((typeof globalThis.CFQ_TOKEN === 'string' && globalThis.CFQ_TOKEN) || await POOL.get('CFQ_TOKEN'));
    acc = cleanKV((typeof globalThis.CFQ_ACCOUNT === 'string' && globalThis.CFQ_ACCOUNT) || await POOL.get('CFQ_ACCOUNT'));
    if (!force) {
      /* 2026-11-10：节流判断改读 Cache API。原来读 KV 判断「10 分钟内探过没有」，
         而 19 个分片并发时各自读到同一个旧时间戳 → 一起探、一起写 KV，
         一小时能写上百次（KV 写免费额度只有 1000/天，这是第二大来源）。 */
      const raw = await caGet(QGATE_KEY) || await POOL.get(QGATE_KEY).catch(() => null);
      if (raw) last = Number((JSON.parse(raw) || {}).t) || 0;
    }
  } catch (e) {}
  if (!tok || !acc) return { skip: 'no_token' };
  if (!force && last && Date.now() - last < 600000) return { skip: 'fresh', at: last };  // 10 分钟节流
  const today = new Date().toISOString().slice(0, 10);
  const q = 'query{viewer{accounts(filter:{accountTag:"' + acc + '"}){d1AnalyticsAdaptiveGroups(' +
    'limit:1,orderBy:[date_DESC],filter:{date_geq:"' + today + '",date_leq:"' + today + '"})' +
    '{dimensions{date}sum{rowsRead rowsWritten}}}}}';
  try {
    const r = await fetch('https://api.cloudflare.com/client/v4/graphql', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + tok, 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: q }),
    });
    const j = await r.json();
    const arr = j && j.data && j.data.viewer && j.data.viewer.accounts &&
      j.data.viewer.accounts[0] && j.data.viewer.accounts[0].d1AnalyticsAdaptiveGroups;
    if (!Array.isArray(arr)) {
      return { skip: 'bad_query', err: (j && j.errors) ? String(JSON.stringify(j.errors)).slice(0, 200) : '' };
    }
    const read = arr[0] ? Number(arr[0].sum.rowsRead || 0) : 0;
    const written = arr[0] ? Number(arr[0].sum.rowsWritten || 0) : 0;
    const p = Math.round(read * 1000 / D1_READ_LIMIT) / 10;   // 一位小数的百分比
    /* 2026-11-10：自动探针结果只落 Cache API（每 colo 一份，本 colo 的闸门据此判断）——
       不占 KV 写额度。手动落值（/api/quota_report）仍写 KV，保证跨数据中心全局生效。 */
    await caPut(QGATE_KEY, JSON.stringify({ p: p, t: Date.now(), read: read, w: written }), 7200);
    _qgPct = p; _qgAt = Date.now();
    return { pct: p, read: read };
  } catch (e) {
    console.error('D1 额度探针失败:', e && e.message);
    return { skip: 'fetch_failed' };
  }
}

// 2026-11-10：加节流。它只是「D1 不可用时的重建缓存」，不是权威数据（entry:/D1 才是），
//   但原来每个写操作（改邮箱 / 改套餐 / 删号 / 改名 / 作废链接）都会整池重读 + 整池重写一份 200KB 单键。
//   现在默认 30 分钟内不重复刷；只有「真正影响兜底正确性」的变更才传 force=true 立刻刷：
//   新增号（否则 D1 抖动时兜底快照里没有这个号 → 漏播）、改 CK（否则拿旧 CK 播 → 白跑）、
//   /api/d1_sync 全表重写。删号不需要 force：墓碑 dead_log 会在 mergePoolKV 里过滤掉残留条目。
const SNAP_MIN_GAP = 1800000;   // 30 分钟

async function refreshPoolSnap(force) {
  if (!d1ok()) return false;
  // 2026-11-09：额度闸门 —— 这一步本身要全池读 682 行（只为写 1 次 KV），≥95% 时跳过。
  if (await d1ReadBlocked()) return false;
  if (!force) {
    try {
      const last = Number(await caGet('poolsnap:at')) || 0;
      if (last && Date.now() - last < SNAP_MIN_GAP) return false;
    } catch (e) { /* 读不到时间戳就照常刷：宁可多写一次，也不能让灾备快照悄悄变旧 */ }
  }
  // 2026-11-08：同样去掉 ORDER BY（改 JS 排，见 d1PoolCmp），省一半读行数；快照内容顺序不变。
  const rows = await d1All('SELECT ' + D1_COLS + ' FROM accounts WHERE pool=?', [POOL_NAME]);
  if (!rows || !rows.length) return false;
  rows.sort(d1PoolCmp);
  try {
    await POOL.put(poolSnapKey(), JSON.stringify(rows.map(d1RowToEntry)));
    try { await caPut('poolsnap:at', String(Date.now()), 3600); } catch (e) {}
    return true;
  } catch (e) { console.error('号池快照写入失败:', e && e.message); return false; }
}

// ---- 每日轮转分配 ----
function dayIndexBJ() {
  const t = new Date(Date.now() + 8 * 3600 * 1000);
  return Math.floor(Date.UTC(t.getUTCFullYear(), t.getUTCMonth(), t.getUTCDate()) / 86400000);
}
function hashStr(s) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
  return h >>> 0;
}
// ---- 登记页访问口令（2026-10-23）----
// 背景：旧邮件正文里带过登记页地址，邮件被转发或页面被搜索收录后，任何人都能打开登记页。
// 需求：互助版网页加口令 music88888，但**软件（APK/EXE）不受影响** —— 它们调的是 /api/*，
// 所以闸门只挂在 GET / 与 /index.html 上，任何 /api/* 都不碰。
// 口令存在 KV 的 PAGE_PASS 键：值为空 = 不启用（改回空字符串即可随时关掉，不用改代码）。
// cookie 里存的是 hashStr('pg:'+口令)，不落明文。
const GATE_COOKIE = 'pgate';
// 2026-10-25：口令闸门仍是白名单式，只列要拦的网页路由，/api/* 一律放行（APK/EXE 不受影响）。
// ⚠️ **不要**把 /console、/admin 加进来：
//   ① 这两页各有自己的强口令（/console 认 KV CONSOLE_PASS 24 位、/admin 认 ADMIN_PASS 16 位），
//      而 PAGE_PASS 是 music88888、发给过全体 263 个成员 —— 用它当第二道锁等于没锁；
//   ② 闸门会 302 跳转，URL 里的 #pw= 免密 hash 在跳转时必丢，CK助手点「进阶控制台」
//      就变成「先输访问口令、再输控制台口令」两遍（2026-10-25 实测复现）。
const PAGE_ROUTES = new Set(['/', '/index.html']);
function gateCookieValue(pass) { return String(hashStr('pg:' + pass)); }
async function pageGate(request, url) {
  let pass = '';
  try { pass = cleanKV(await POOL.get('PAGE_PASS')); } catch (e) {}
  if (!pass) return null;                                  // 未配置口令 → 直接放行
  const want = gateCookieValue(pass);
  if (url.searchParams.get('k') === pass) {                 // 带对口令 → 种 cookie，去掉 query 后回原页面
    return new Response(null, { status: 302, headers: {
      'Location': url.pathname || '/',
      'Set-Cookie': `${GATE_COOKIE}=${want}; Max-Age=31536000; Path=/; HttpOnly; SameSite=Lax`,
    } });
  }
  const ck = request.headers.get('Cookie') || '';
  const m = ck.match(new RegExp('(?:^|;\\s*)' + GATE_COOKIE + '=([^;]+)'));
  if (m && m[1] === want) return null;                      // cookie 已通过 → 放行
  return new Response(GATE_HTML, {
    status: 401,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}
function seededShuffle(a, seed) {
  let s = (seed >>> 0) || 1;
  for (let i = a.length - 1; i > 0; i--) {
    s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0;
    const j = s % (i + 1); const t = a[i]; a[i] = a[j]; a[j] = t;
  }
  return a;
}
// 把「一行号池数据」规整成计划用的结构：D1 行（snake）与 KV entry（camel）都能喂进来。
function planRow(r) {
  if (!r) return null;
  const noListen = r.no_listen ? 1 : (r.noListen ? 1 : 0);
  // 2026-11-01：公益号标记（pub=1）。只帮别人听，自己登记的歌不进互听歌环
  //（"自己的歌不需要别人听"），也不参与签到。列缺失时按 0 处理，老数据行为不变。
  const pub = r.pub ? 1 : 0;
  // 是否有 CK：D1 主路径只回 0/1 的 hasck（省传输），KV 兜底路径行里直接有 ck。
  // 没有 CK 的行播不了，绝不能占听众名额 —— 否则那首歌每天白少一个听众，且谁也发现不了。
  const hasCk = (r.hasck !== undefined && r.hasck !== null)
    ? (Number(r.hasck) === 1)
    : (typeof r.ck === 'string' ? !!r.ck.trim() : true);
  return {
    pool: String(r.pool || POOL_NAME),
    uid: r.uid != null ? String(r.uid) : '',
    name: String(r.name || ''),
    song: String(r.song || ''),
    ck: String(r.ck || ''),
    email: String(r.email || ''),
    hasCk: hasCk,
    no_listen: noListen,
    // 2026-11-04：CK 已确认失效且已通知号主重登（report_dead 的 relogin 分支写的）。
    // KV 兜底路径没有这一列 → undefined → false，行为与以前一致。
    relogin: r.relogin_at ? 1 : 0,
    pub: pub,
    added: String(r.added || ''),
    exp: String(r.exp || ''),
  };
}

// 纯计算（无 I/O）：D1 主路径与 KV 兜底共用同一套轮转逻辑，保证两条路算出的窗口完全一致。
// 2026-10-29：分片键 = uid 哈希桶（替掉原来的「列表下标 i % jobs」）。
// 背景（10-28 hz 覆盖率掉到 64.2% 的根因）：/api/assign 每次请求都重算 buildPlan，
// 再用 ownPool.filter((_, i) => i % jobs === job) 按「数组下标」分片。而一整夜跑的过程中
// 死号会被不断删除（实测全池 531 → 434），下标整体前移 ⇒ 同一个号被分到 2~3 片
//（实测 91 个号重复、白烧 113 个席位），另有 125 个计划号任何一片都没轮到。
// 改成按 uid 哈希取模后，每个号固定落在自己那一桶：池里增减只会影响它自己，
// 不会连锁漂移；代价是各片号数不再绝对均匀（约 ±40%，最重一片约为均值的 2 倍，仍在跑得完的范围）。
// 2026-11-04：分片键叠「日期盐」。原先纯 uid 哈希 => 同一批号天天被分到同一片，
// 也就是天天跑在同一台 VM 上：网易看到的不是「一个 IP 上有 6 个号」，而是
// 「这 6 个号永远同进同出，只是共用的 IP 每天在换」—— 真实用户不会这样，是结构性指纹。
// 盐取 plan.day（run.yml 的 ASSIGN_DAY / 定向补跑的 DAY_OVERRIDE），整轮任务内恒定，
// 所以「NS_OVERRIDE + ONLY_SLICES」补跑仍能精确复现失败那一轮的分片。
function sliceBucket(uid, jobs, salt) {
  const s = String(uid || '') + (salt ? '|' + salt : '');
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;      // FNV-1a 乘 16777619，Math.imul 保证 32 位不丢精度
  }
  h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b) >>> 0;   // murmur3 fmix32 收尾，避免低位分布不均
  h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35) >>> 0;
  h ^= h >>> 16;
  return (h >>> 0) % Math.max(1, jobs);
}

/* ============================================================================
   首周加速分配（2026-11-08）
   ----------------------------------------------------------------------------
   口径前提（别搞错）：650 = 近 30 日「不同听众」累计有效播放，平台去重口径是
   「同听众 + 同歌 + 同一天」。所以一首歌今天能涨多少，只取决于今天有多少个
   不同的号去听它；跨天重复听仍然计数，同一天同一号重复才无效。

   原来的平均分配：M 个听众每人听 p 首，总槽位 M*p 摊给 L 首歌 =>
   每首歌每天刚好 M*p/L ≈ 32 个听众，650/32 要爬 21 天，这就是「首月 22 天」的来源。

   改法：按「歌主入池天数」给每首歌定目标听众数，而不是一律 32。
     入池 1~7 天  : 118 人/天（= 108 理论值 + skip_prob 补偿，7 个自然日内冲满 100%）
     入池 8~21 天 : 32 人/天（与现状一致，在途客户零感知）
     入池 22 天+  : 25 人/天（早就满了；维持 100% 的下限是 22，留 14% 余量）
   总槽位 S = 各歌目标之和，每人每晚听几首 per ≈ S/M。
   注意 per 会从 32 涨到 52 左右：这不是「提高每日上限」，30 从来是下限不是上限，
   只是新号那几首歌要多被 76 个人听，人得从别人身上匀出来。

   分配算法：每首歌一个「听众窗口」，起点在归一化号空间里按天线性推进
     ① 听众先按 uid 稳定排序（窗口 = 索引区间，索引含义每天必须一致）
     ② 第 j 首歌起点 pos = (hash(歌)/2^32 + day*目标数/BASE_M) % 1，
        取 pos*M 起连续「目标数」个号 => 这首歌今天就恰好被这么多人听到
     ③ 每首歌每天按自己的目标数前进，所以加速档每天精确 +108 个新听众
   ⚠ 三条踩过的坑，改之前必读（都能让加速「静默失效」，不报错、只是不满 650）：
     ① 号必须按 uid 排序。不排的话同一个号今天第 5、明天第 300，日间推进全乱。
     ② 起点必须用归一化比例 pos ∈ [0,1)，不能写 (h + day*t) % M。池子每天
        新增约 31 个号，M 一变 mod 就整体错位：实测第 3 天起每天只推进 77 位
        （应为 108），7 天累计从 756 掉到 530，首月根本满不了。
     ③ BASE_M 必须 <= 典型 M（当前 743），保证每天推进的号位数 >= 目标数，
        否则窗口重叠、同一批人被重复听，白烧算力。
   实测（本地镜像 M=743 / L=742 / S=38,522）：per=52，每号首数 p50=52 / max=60
   （已配平，见下方 cap 逻辑），加速档 108 首的歌听众 min=107 / 中位=108，
   7 天累计 672 >= 650 => 「入池第 7 天满」。整轮 743 号由实测 2.0h 涨到约 3.4h，
   仍在快照门闩（11:40）之前，不需要提前发令。
   ============================================================================ */
const ACCEL_ON = true;          // 总开关：改 false 立刻回到原来的平均分配（应急回滚用）
const ACCEL_DAYS = 7;           // 入池 1~N 天算「加速档」
// 2026-11-09：108 → 118。108 是「650/6」的纯理论值，但 run.py 的 skip_prob（默认 0.08）会
// 随机跳过约 8% 的曲目（模拟真实切歌），那部分不计有效播放。按 108 算实际只有 ~99/天，
// 7 天 693 在「人-天次数」口径下刚刚够、在「不同听众」口径下只有 618 不够。
// 118 是 108 / 0.92 上取整，7 天 826 → 有效 ~760，两种口径都留得住余量。
const ACCEL_PER_DAY = 118;      // 加速档：每首歌每天要多少个不同听众（已含 skip_prob 补偿）
const KEEP_PER_DAY = 32;        // 在途档：与现状一致，不动存量客户的速度
const IDLE_PER_DAY = 25;        // 满档：已 100%，维持住的下限是 22
function daysBetween(from, to) {                 // to - from，单位天；非法值按「很远」处理
  const t1 = Date.parse(String(from || '').slice(0, 10) + 'T00:00:00Z');
  const t2 = Date.parse(String(to || '').slice(0, 10) + 'T00:00:00Z');
  if (!isFinite(t1) || !isFinite(t2)) return 999;
  return Math.floor((t2 - t1) / 86400000);
}
function accelTargetOf(added, today) {
  const d = daysBetween(added, today);
  if (d <= 0) return 0;                          // 当天登记的号已在 live 里被滤掉，兜底返回 0
  if (d <= ACCEL_DAYS) return ACCEL_PER_DAY;
  if (d <= 21) return KEEP_PER_DAY;
  return IDLE_PER_DAY;
}
function buildPlanAccel(live, songs, listeners, today, idle) {
  const M = listeners.length, L = songs.length;
  if (!M || !L) return { ok: false, msg: '可用号或歌曲为空', m: M, l: L, idle, plans: [] };
  // 每首歌的目标按「登记它的号里入池最早的那个」算：同一首歌被多个号登记时，
  // 只要有一个是新号，这首歌就享受加速（宁可多给，不要漏掉首月客户）。
  const owner = {};
  for (const r of live) {
    if (r.pub) continue;                         // 公益号的歌不进歌环，与 songs 的过滤保持一致
    if (r.relogin) continue;                     // 失效号同理，见 songs 处 2026-11-08 的说明
    const s = String(r.song || ''); if (!s) continue;
    const a = String(r.added || '');
    if (!owner[s] || (a && a < owner[s])) owner[s] = a;
  }
  const tgt = songs.map(s => accelTargetOf(owner[s], today));
  let S = 0;
  for (const t of tgt) S += t;
  if (!S) return { ok: false, msg: '目标听众全为 0', m: M, l: L, idle, plans: [] };
  // 单班时长保险：某天新号扎堆（例如单日新增 78 个）会把「平均每人首数」顶到 60+，
  // 单班时长爆到 5h 以上就会顶到 09:00 快照门闩。超限就等比缩放目标数 ——
  // 那天加速档拿不满 108（等比稀释），但整轮一定跑得完，不会丢播放。
  // 2026-11-09：按池子规模自适应。大池子（hz 681 号、34 号一片 → 每片要跑 1.7 轮）per=62
  // 已经顶到快照门闩；小池子（dz 117 号、6 号一片 → 只跑 1 轮）per 83 整轮也才 3 小时，
  // 用 62 反而把加速档等比稀释掉 —— 实测 dz 118 → 88/天，7 天只剩 619，再打 8% 跳过不到 650。
  // 不要写成「按群名判断」：两仓算法必须用同一份输入算出同一份 plan，只能按 M 这个
  // 两边都能独立算出来的量来分叉。
  // 2026-11-09 二次修正：62/90 是写死的阈值，池子和分片一变就失准 ——
  //   M=682 时 62 只剩 8% 余量（新号稍多一点就整批稀释），M=1200 时又该收到 60 却仍是 62。
  // 改成按「门闩 ÷ 波数」推导，输入全是 worker 自己能独立算出来的量（两仓才能算出同一份 plan）：
  //   单号实测时长 ≈ (per + 8混听) × 0.92(skip_prob) × 99s ≈ (per+8) × 1.52 分钟
  //     —— 依据：11-07 relay 实测 212min，per=32、21 片、最重片 3 轮、2 波，反推 99s/首。
  //   波数 = ceil(ceil(M/APS) / 20)，APS 与并发取自 run.yml（现值 12 / 20）。
  //   门闩 520 分钟：02:44 起跑 → 11:24，留 16 分钟给快照主采。
  // ⚠ 改 run.yml 的 ACCOUNTS_PER_SLICE / ACCOUNT_PARALLEL 公式必须同步改下面 PER0_ASSUME/PAR_ASSUME，
  //   偏大 = 单班顶穿门闩被 kill，偏小 = 加速档被白白等比稀释（都是静默的，不报错）。
  /* 2026-11-10：APS 不再写死 12 —— 只把那个值当「小池子默认值」。
     原因：run.yml 的 ACCOUNTS_PER_SLICE 改成「按目标波数自动反算」后，per 会随池子人数变
     （776 号 = 13、1200 号 = 20），这里若仍写死 12，waves 会多算一波 → PER_CAP 偏小 →
     加速档被白白等比稀释（静默的）。两边必须逐字一致，公式：
       per = clamp(ceil(M / (TARGET_WAVES × JOB_CONC)), 8, floor(PAR / 1.7))
     floor(PAR/1.7) 的 1.7 = 「哈希最重片 ÷ 平均片」的实测倍率上限。sliceBucket 11-10 实测：
       ns=20 → 1.28×、ns=60 → 1.54×、ns=100 → 2.08×；取 1.7 是保证最重片 ≤ ACCOUNT_PARALLEL，
       不出现「片内跑第 2 轮」（那会把该片时长直接翻倍，整轮也多一跳）。
     M < 500 走旧值 12：dz 是 118 号 / 6 号一片 / 1 波，用新公式会把 waves 从 1 抬到 3、
     PER_CAP 从 334 砍到 106 —— 一旦某个加速日 S/M 超过 106 就会整批稀释，那是 dz 现在
     唯一能保 650 的档位。按 M 分叉（不是按群名），两仓输入相同就一定能算出同一份 plan。 */
  /* 2026-11-11：PAR 也不再写死 —— 跟着 per 走（与 run.yml plan 的自动公式逐字一致）：
       per0 = ceil(M / (TARGET_WAVES × JOB_CONC))
       PAR  = clamp(ceil(per0 × 2.0), 24, 48)
       per  = min(per0, floor(PAR / 2.0))
     2.0 = 「哈希最重片 ÷ per」的安全倍率（ns≈60 实测 1.54~1.88×），PAR ≥ 2×per 保证最重片
     不跨轮。11-10 实测教训：PAR 死 24、813 号 → per=14 → 有一片 26 个号 > 24 跨第 2 轮，
     整轮 8.8h；PAR 自动到 28 后同一片 1 轮，整轮 7.0h。模拟（tmp/_sim_autopar_1111.mjs）：
     813~1440 号整轮都稳定 7.0~7.7h、恒 3 波 1 轮，池子增长不用再手改任何数字。
     M < 500（dz）分支不变：APS=12、PAR_ASSUME 只在此分支不参与 per 计算，仍给 24。 */
  const JOB_CONC = 20, TARGET_WAVES = 3, KNIFE_MIN = 520, MIN_PER_SONG = 1.52;
  const PER0_ASSUME = M >= 500 ? Math.max(8, Math.ceil(M / (TARGET_WAVES * JOB_CONC))) : 12;
  const PAR_ASSUME = M >= 500 ? Math.min(48, Math.max(24, Math.ceil(PER0_ASSUME * 2.0))) : 24;
  const APS_ASSUME = M >= 500
    ? Math.max(8, Math.min(PER0_ASSUME, Math.floor(PAR_ASSUME / 2)))
    : 12;
  const waves = Math.max(1, Math.ceil(Math.ceil(M / APS_ASSUME) / JOB_CONC));
  const PER_CAP = Math.max(16, Math.floor(KNIFE_MIN / waves / MIN_PER_SONG) - 8);
  let capped = 0;
  if (S / M > PER_CAP) {
    capped = 1;
    const ratio = PER_CAP * M / S;
    for (let j = 0; j < L; j++) tgt[j] = Math.max(1, Math.round(tgt[j] * ratio));
    S = 0;
    for (const t of tgt) S += t;
  }
  // ---- 分配模型：每首歌一个「听众窗口」，起点在归一化号空间里按天线性推进 ----
  // 2026-11-08 实测踩出来的三条，改动前务必读完，否则加速会静默失效：
  //   ① 号必须先按 uid 稳定排序。窗口是「号的索引区间」，索引含义每天必须一致；
  //      否则同一个号今天排第 5、明天排第 300，日间推进就完全乱了。
  //   ② 起点用归一化比例 pos ∈ [0,1) 再乘 M，**不能**写 `(h + day*t) % M`。
  //      池子每天新增约 31 个号，M 一变 mod 就整体错位：实测第 3 天起每天只能
  //      推进 77 位（应为 108），7 天累计从 756 掉到 530，首月根本满不了。
  //      归一化后 pos 每天推进 t/BASE_M，与 M 无关 —— 实测连续 5 天每天精确 +108。
  //   ③ BASE_M 必须 <= 典型 M（当前 743），保证每天推进的号位数 >= tgt，
  //      否则窗口会重叠、白白重复听同一批人。
  const BASE_M = 650;
  const day = Math.floor(Date.parse(today + 'T00:00:00Z') / 86400000);
  const order = new Array(M);
  for (let i = 0; i < M; i++) order[i] = i;
  order.sort((a, b) => (listeners[a].uid < listeners[b].uid ? -1 : listeners[a].uid > listeners[b].uid ? 1 : 0));
  const buckets = new Array(M);
  for (let j = 0; j < L; j++) {
    const t = tgt[j];
    if (!t) continue;
    let pos = (hashStr(songs[j]) / 4294967296 + day * t / BASE_M) % 1;
    if (pos < 0) pos += 1;
    const start = Math.floor(pos * M) % M;
    // 2026-11-09：t 可能 > M（D1 挂掉走 KV 兜底、池子里只剩几十个号时），原来 (start+k)%M
    // 会把同一首歌塞给同一个号两次 —— 同一天同号重复听完全不计播放，白烧一整首的时长。
    const times = Math.min(t, M);
    for (let k = 0; k < times; k++) {
      const i = (start + k) % M;
      const b = buckets[i];
      if (b) b.push(j); else buckets[i] = [j];
    }
  }
  const plans = [];
  // ---- 配平：桶分配是「每首歌各自挑窗口」，桶大小天然不均（实测 p99 会到 per 的 1.3 倍）。
  // 而整轮时长由**最慢的那个号**决定，不均就等于白拖时间。把超过 cap 的歌匀给不足 per 的号，
  // 每首歌的听众总数不变（还是 tgt 个人听），只是换了几个号。
  const per = Math.max(1, Math.round(S / M));
  const cap = per + 8;
  const over = [], thin = [];
  for (let i = 0; i < M; i++) {
    const b = buckets[i] || (buckets[i] = []);
    if (b.length > cap) {
      for (let x = cap; x < b.length; x++) over.push([b[x], i]);
      b.length = cap;
    }
    if (b.length < per) thin.push(i);
  }
  let ti = 0, nDone = 0;
  for (let n = 0; n < over.length && thin.length; n++) {
    nDone = n + 1;
    const j = over[n][0], src = over[n][1];
    let placed = false;
    for (let k = 0; k < thin.length; k++) {
      const i = thin[(ti + k) % thin.length];
      const b = buckets[i];
      // 2026-11-09：必须同时排除「这首歌主人自己的桶」。原来只查 indexOf(j)，没查 own：
      // 匀给歌主本人时，出 plan 阶段 s !== own 会把它剔掉 ⇒ 这首歌白少一个听众。
      // 实测「目标 108 人/天」那批 min=107（应是 108）就是这么来的。
      if (b.length >= per || b.indexOf(j) >= 0) continue;
      if (listeners[order[i]].song === songs[j]) continue;
      b.push(j); placed = true;
      ti = (ti + k + 1) % thin.length;
      break;
    }
    // 找不到空位就留在原桶：宁可那一个号慢一点，也不能让这首歌少一个听众
    if (!placed) buckets[src].push(j);
  }
  // 2026-11-09：上面循环条件带 thin.length，若初始所有桶都 >= per 就一次都不执行，
  // 已经被 cap 截断进 over 的歌就凭空消失（那首歌少听众）。概率极低，但撞上就是掉播放，
  // 所以补一趟：没处理到的 over 项一律放回原桶（宁可该号多听一首，也不能让歌少一个听众）。
  for (let n = nDone; n < over.length; n++) {
    const j = over[n][0], src = over[n][1];
    if (buckets[src].indexOf(j) < 0) buckets[src].push(j);
  }
  let maxPlays = 0, sumPlays = 0;
  for (let oi = 0; oi < M; oi++) {
    const it = listeners[order[oi]];
    const own = it.song;
    const bj = buckets[oi];
    const picks = [];
    // 桶里就是「窗口覆盖到本号」的歌，天然不重复（每首歌只推一次），
    // 只需剔除自己的歌。所以这里不需要 Set 去重，比旧版省一半 CPU。
    if (bj) for (let x = 0; x < bj.length; x++) {
      const s = songs[bj[x]];
      if (s !== own) picks.push(s);
    }
    seededShuffle(picks, hashStr(it.uid + ':' + day));
    if (picks.length > maxPlays) maxPlays = picks.length;
    sumPlays += picks.length;
    plans.push({ pool: it.pool, uid: it.uid, name: it.name, song: own,
                 ck: it.ck, email: it.email, pub: it.pub ? 1 : 0, plays: picks });
  }
  const perAvg = Math.round(sumPlays / M);
  return { ok: true, day: today, m: M, l: L, p: perAvg, plans, idle,
           accel: { on: 1, days: ACCEL_DAYS, perDay: ACCEL_PER_DAY, slots: S, per: perAvg,
                    max: maxPlays, capped: capped } };
}

function buildPlanFrom(rows, today) {
  const live = rows.filter(r => {
    const added = String(r.added || '');
    if (added && added >= today) return false;               // 当天新登记的次日才跑
    const exp = String(r.exp || '');
    // 2026-11-05：到期号不再删除，改成降级为公益号（pub=1）。这类号虽然 exp 已过期，
    // 但仍然要留在 listeners 里帮别人听 —— 否则「不删号」就只剩个空壳，播放量反而掉了。
    // 它们的歌不会进歌环（下面 songs 按 !pub 过滤），所以不会反过来占别人的播放次数。
    if (exp && exp !== 'forever' && exp < today && !r.pub) return false;
    return true;
  });
  // 2026-11-01：公益号登记的歌不进互听歌环 —— 它的号主明确说「自己的歌不需要别人听」，
  // 留在 songs 里会平白分走别的号的播放次数。注意只从歌环剔除，账号本身仍留在 listeners
  // 里照常帮别人听（这正是公益号的用途），song 字段也不清（随时能改回普通号）。
  // 2026-11-08：CK 已确认失效的号（relogin 非空）同样不进歌环。原来是「人摘出听众环、
  // 歌留在歌环」，等于这几个号只收不听 —— 白占 6/748 的播放次数，还让 L/M 虚高。
  // 号主重新登记清空 relogin_at 后，歌会自动回到歌环，不需要人工干预。
  const songs = [...new Set(live.filter(r => !r.pub && !r.relogin).map(r => String(r.song || '')).filter(Boolean))].sort();
  const seen = new Set();
  const listeners = [];
  const idle = [];                                           // 只收不听：不进播放环，但要下发去签到/查工作台/验活
  for (const r of live) {
    const uid = String(r.uid || '');
    const key = String(r.pool) + ':' + uid;
    if (!uid || seen.has(key)) continue;
    if (!r.hasCk) continue;                                  // 空 CK 占位行不占听众名额
    seen.add(key);
    const item = { pool: String(r.pool), uid, name: r.name || '', song: r.song || '',
                   ck: r.ck, email: r.email || '', pub: r.pub ? 1 : 0 };
    if (r.no_listen) { idle.push(item); continue; }
    // 2026-11-04：CK 已确认失效、账号仍在（判死加固 B 保留的那批）→ 摘出听众环。
    // 它留下来只会占一个「应跑」名额然后每天验活失败：coverage 天天缺这几个，页面上
    // 又看不出原因。放进 idle 而不是直接丢：号仍每轮验活，号主重新登记后 CK 变化会把
    // relogin_at 清空，下一轮自动回到听众环。
    // 2026-11-08 补：歌也不再留在 songs 里（原来只摘人不摘歌，等于让它们白占播放次数）。
    if (r.relogin) { idle.push(item); continue; }
    listeners.push(item);
  }
  const M = listeners.length, L = songs.length;
  if (!M || !L) return { ok: false, msg: '可用号或歌曲为空', m: M, l: L, idle, plans: [] };
  // 2026-11-08：首周加速走「每首歌独立听众窗口」（见上方 buildPlanAccel 的口径说明）。
  // ACCEL_ON=false 时下面这套平均分配原样保留，改一个常量就能回滚，不需要回滚整个文件。
  if (ACCEL_ON) return buildPlanAccel(live, songs, listeners, today, idle);
  // p：先按「每首歌每天 ASSIGN_TARGET+1 个听众」反推，再夹进 [1, L-1]。
  // 2026-10-22 修正：原写法 Math.max(8, Math.min(L-1, x)) 在 L<9 时 p>L-1，每人取不满 p 首。
  const p = Math.max(1, Math.min(Math.max(8, Math.ceil((ASSIGN_TARGET + 1) * L / M)), Math.max(1, L - 1)));
  const day = Math.floor(Date.parse(today + 'T00:00:00Z') / 86400000);
  const off = ((day * p) % L + L) % L;
  const plans = [];
  for (let i = 0; i < M; i++) {
    const it = listeners[i];
    const base = Math.floor(i * L / M);
    const own = it.song;
    const picks = [];
    for (let j = 0; picks.length < p && j < L; j++) {
      const sid = songs[(base + off + j) % L];
      if (sid === own) continue;                             // 绝不听自己
      picks.push(sid);
    }
    seededShuffle(picks, hashStr(it.uid + ':' + day));
    plans.push({ pool: it.pool, uid: it.uid, name: it.name, song: own,
                 ck: it.ck, email: it.email, pub: it.pub ? 1 : 0, plays: picks });
  }
  return { ok: true, day: today, m: M, l: L, p, plans, idle };
}

// 返回全量 listeners 的播放计划；调用方按 i % jobs 取自己那一批。
// 覆盖性证明：第 i 个号的窗口起点 base=floor(i*L/M)，长度 p ⇒ 任一歌曲位置被
// 恰好 p*M/L（向上取整后 ≥p）个窗口覆盖 ⇒ 每首歌每天都有听众，且方差极小。
// 每日轮转：offset 每天 +p（=窗口长度）⇒ 相邻两天窗口完全不重叠 ⇒ 听众集合全换。
async function buildPlan(dayStr) {
  // dayStr：整轮任务统一的「日期锚点」（由 run.yml 的 plan job 下发）。
  // 不传则用北京时间今天。锚定它的原因：号池大到一晚跑不完时会分成多波，
  // 若跨过午夜，各波会算出不同的轮转偏移 —— 那样有的歌被听两遍、有的没人听。
  const today = /^\d{4}-\d{2}-\d{2}$/.test(dayStr || '') ? dayStr : beijingDate();
  // 两群共用一个 D1：歌环与听众环都按「全池」计算，本 worker 只投递自己群的那批号。
  // 这样跨群互听继续有效（主群的号也会听到定制群的歌），且两边算出的计划完全一致。
  // 注意 SELECT 里那个 hasck：只回 0/1，用来判断「这条能不能播」，比把 ck 整列拉回来省 200 倍传输。
  // 2026-10-22：D1 不可用时用 KV 逐号备份兜底（以前直接返回失败 → run.py 回退到冻结的
  // Secrets 分片，1500 号时那一晚只有 212 个号在跑，而且 job 还是绿的）。
  // KV 里只有本群的号，跨群互听会退化成「只听本群」，但绝不会变成 0 个号。
  const planKvFallback = async () => {
    try {
      const kv = await mergePoolKV();
      if (kv && kv.length) {
        const plan = buildPlanFrom(kv.map(planRow), today);   // KV 行自带 ck，planRow 会判空
        plan.src = 'kv';
        return plan;
      }
    } catch (e) { console.error('buildPlan 的 KV 兜底也失败:', e && e.message); }
    return null;
  };
  // 2026-11-09：额度闸门 —— ≥95% 时这一条（全表 + ORDER BY，每片一次）不要再打 D1，
  // 直接走 KV 逐号备份：跨群互听退化为只听本群，但号一个都不会少、整班不会归零。
  if (await d1ReadBlocked()) {
    console.log('D1 读额度 ≥' + QGATE_HOT + '%，buildPlan 走 KV 备份');
    const pk = await planKvFallback();
    if (pk) return pk;
  }
  const rows = await d1All("SELECT pool,uid,name,song,no_listen,pub,added,exp,relogin_at,"
    + "(CASE WHEN ck IS NULL OR TRIM(ck)='' THEN 0 ELSE 1 END) AS hasck "
    + "FROM accounts ORDER BY pool, uid");
  if (rows) return buildPlanFrom(rows.map(planRow), today);
  console.error('D1 查询失败，buildPlan 回退 KV 逐号备份');
  const pk2 = await planKvFallback();
  return pk2 || { ok: false, msg: 'D1 未绑定或查询失败，且 KV 兜底无数据' };
}

/* ============================================================================
   2026-11-09：当轮 plan 名单快照（D1 表 plan_snap）
   ----------------------------------------------------------------------------
   要解决的问题：/api/coverage 的 expected 原来用「当下实时 buildPlan」算、ran 用「当天 runs 表」，
   两边根本不是同一时刻的集合。白天池子一动（删号 / 新登记 / 到期降公益 / CK 失效摘出环），就会：
     ① 假报缺号：号早上还在 expected 里，昨晚那轮压根没它（11-09 报的「缺 13」有 4 个属于这类）；
     ② 漏掉真缺号：号昨晚该跑没跑、今天上午被删 → 从 expected 里消失，缺口神隐。
   改法：每轮 plan job 第一次调 /api/pool_stat 时，把本池应跑名单落一行快照；
   之后全天的补跑、控制台、/api/coverage 都对齐这份快照。**首轮 winner，补跑不覆盖**——
   同一轮任务的「应跑名单」只能有一个版本，否则补跑越多口径越乱。
   为什么存 D1 不存 KV：两群共用同一张库，而控制台一屏要同时显示 hz/dz 两池口径，
   存 KV 的话本 worker 读不到对端那份。
   成本：一行（JSON 数组约 8KB），每池每天写 1 次、读 1 次。D1 读失败时返回 null，
   调用方回退实时 buildPlan（行为和改之前一致），绝不把「读不到」当成「没有快照」。
   ============================================================================ */
async function planSnapGet(day, pool) {
  if (!d1ok()) return null;
  try {
    const rows = await d1All('SELECT uids,n,src,at FROM plan_snap WHERE day=? AND pool=?',
                             [String(day), String(pool)]);
    if (!rows || !rows.length) return null;          // null = 读失败，[] = 真没有
    let uids = [];
    try { uids = JSON.parse(rows[0].uids) || []; } catch (e) { return null; }
    if (!Array.isArray(uids) || !uids.length) return null;
    return { pool: String(pool), uids: uids.map(String), n: Number(rows[0].n) || uids.length,
             src: String(rows[0].src || ''), at: String(rows[0].at || '') };
  } catch (e) { return null; }
}

// 一次取回当天所有池的快照（控制台首屏用，最多 2 行）
async function planSnapAll(day) {
  if (!d1ok()) return null;
  try {
    const rows = await d1All('SELECT pool,uids,n,src,at FROM plan_snap WHERE day=?', [String(day)]);
    if (!rows) return null;
    const out = {};
    for (const r of rows) {
      try {
        const u = JSON.parse(r.uids);
        if (Array.isArray(u) && u.length) {
          out[r.pool] = { uids: u.map(String), n: Number(r.n) || u.length,
                          src: String(r.src || ''), at: String(r.at || '') };
        }
      } catch (e) {}
    }
    return out;
  } catch (e) { return null; }
}

async function planSnapPut(day, pool, uids, src) {
  if (!d1ok() || !uids || !uids.length) return false;
  try {
    // 先看这一池今天有没有落过：null=读失败（不写，免得覆盖已有快照）/ 非空=补跑，不覆盖
    const ex = await d1All('SELECT day FROM plan_snap WHERE day=? AND pool=?',
                           [String(day), String(pool)]);
    if (ex === null || ex.length) return false;
    const arr = uids.map(String);
    return await d1Run('INSERT OR IGNORE INTO plan_snap (day,pool,uids,n,src,at) VALUES (?,?,?,?,?,?)',
      [String(day), String(pool), JSON.stringify(arr), arr.length, String(src || 'd1'), bjStamp()]);
  } catch (e) {
    console.error('plan_snap 写入失败（coverage 自动回退实时口径）:', e && e.message);
    return false;
  }
}

/* ============================================================================
   方案C（2026-11-08）：网页自助扫码登记
   ----------------------------------------------------------------------------
   买家拿到一次性链接 /r/<8 位码>：打开 → 网页自己出二维码 → 网易云 APP 扫码确认
   → 自动取回 MUSIC_U → 填歌曲链接/手机号/邮箱 → 提交登记。token 用完即废。

   为什么要在 worker 里自己写 QR 编码器：Workers 不能加载外部脚本，买家手机也
   未必能访问第三方 CDN，二维码必须在服务端就地生成 PNG（base64 内嵌，长按可存相册）。
   算法与 Python qrcode 库逐位等价（byte 模式 / ECC M / 版本 1-20），
   交叉验证 102 个用例（含真实扫码 URL）矩阵完全一致。
   ============================================================================ */

/* ---- GF(256) ---- */
const QR_GF_EXP = new Uint8Array(512);
const QR_GF_LOG = new Uint8Array(256);
(function () {
  let x = 1;
  for (let i = 0; i < 255; i++) { QR_GF_EXP[i] = x; QR_GF_LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; }
  for (let j = 255; j < 512; j++) QR_GF_EXP[j] = QR_GF_EXP[j - 255];
})();
function qrMul(a, b) { return (a === 0 || b === 0) ? 0 : QR_GF_EXP[QR_GF_LOG[a] + QR_GF_LOG[b]]; }

/* RS 分块表：QR_RS[版本-1][档位] = [块数,总码字,数据码字, ...]；档位 0=L 1=M */
const QR_RS = [[[1,26,19],[1,26,16],[1,26,13],[1,26,9]],[[1,44,34],[1,44,28],[1,44,22],[1,44,16]],[[1,70,55],[1,70,44],[2,35,17],[2,35,13]],[[1,100,80],[2,50,32],[2,50,24],[4,25,9]],[[1,134,108],[2,67,43],[2,33,15,2,34,16],[2,33,11,2,34,12]],[[2,86,68],[4,43,27],[4,43,19],[4,43,15]],[[2,98,78],[4,49,31],[2,32,14,4,33,15],[4,39,13,1,40,14]],[[2,121,97],[2,60,38,2,61,39],[4,40,18,2,41,19],[4,40,14,2,41,15]],[[2,146,116],[3,58,36,2,59,37],[4,36,16,4,37,17],[4,36,12,4,37,13]],[[2,86,68,2,87,69],[4,69,43,1,70,44],[6,43,19,2,44,20],[6,43,15,2,44,16]],[[4,101,81],[1,80,50,4,81,51],[4,50,22,4,51,23],[3,36,12,8,37,13]],[[2,116,92,2,117,93],[6,58,36,2,59,37],[4,46,20,6,47,21],[7,42,14,4,43,15]],[[4,133,107],[8,59,37,1,60,38],[8,44,20,4,45,21],[12,33,11,4,34,12]],[[3,145,115,1,146,116],[4,64,40,5,65,41],[11,36,16,5,37,17],[11,36,12,5,37,13]],[[5,109,87,1,110,88],[5,65,41,5,66,42],[5,54,24,7,55,25],[11,36,12,7,37,13]],[[5,122,98,1,123,99],[7,73,45,3,74,46],[15,43,19,2,44,20],[3,45,15,13,46,16]],[[1,135,107,5,136,108],[10,74,46,1,75,47],[1,50,22,15,51,23],[2,42,14,17,43,15]],[[5,150,120,1,151,121],[9,69,43,4,70,44],[17,50,22,1,51,23],[2,42,14,19,43,15]],[[3,141,113,4,142,114],[3,70,44,11,71,45],[17,47,21,4,48,22],[9,39,13,16,40,14]],[[3,135,107,5,136,108],[3,67,41,13,68,42],[15,54,24,5,55,25],[15,43,15,10,44,16]]];
const QR_ALIGN = [[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90]];

function qrGenPoly(n) {
  let g = [1];
  for (let i = 0; i < n; i++) {
    const ng = new Array(g.length + 1).fill(0);
    for (let j = 0; j < g.length; j++) { ng[j] ^= g[j]; ng[j + 1] ^= qrMul(g[j], QR_GF_EXP[i]); }
    g = ng;
  }
  return g;
}
function qrRsEc(data, ecLen) {
  const g = qrGenPoly(ecLen);
  const res = data.slice();
  for (let i = 0; i < ecLen; i++) res.push(0);
  for (let i = 0; i < data.length; i++) {
    const coef = res[i];
    if (!coef) continue;
    for (let j = 0; j < g.length; j++) res[i + j] ^= qrMul(g[j], coef);
  }
  return res.slice(data.length);
}
function qrBitLen(x) { let n = 0; while (x) { n++; x >>>= 1; } return n; }
function qrBch(data, g, shift) {
  let d = data << shift;
  const gd = qrBitLen(g);
  while (qrBitLen(d) - gd >= 0) d ^= g << (qrBitLen(d) - gd);
  return ((data << shift) | d) >>> 0;
}

/* 数据编码 + 分块交织；超出 V20 容量返回 null */
function qrBuild(text, ecc) {
  const bytes = new TextEncoder().encode(text);
  const which = ecc === 'L' ? 0 : 1;
  let ver = 0, spec = null, cap = 0;
  for (let v = 1; v <= 20; v++) {
    const s = QR_RS[v - 1][which];
    let c = 0;
    for (let i = 0; i < s.length; i += 3) c += s[i] * s[i + 2];
    const cc = v <= 9 ? 8 : 16;
    if (4 + cc + bytes.length * 8 <= c * 8) { ver = v; spec = s; cap = c; break; }
  }
  if (!ver) return null;

  const bits = [];
  const put = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  put(4, 4);                                    /* byte mode */
  put(bytes.length, ver <= 9 ? 8 : 16);
  for (let i = 0; i < bytes.length; i++) put(bytes[i], 8);

  const limit = cap * 8;
  for (let i = 0, t = Math.min(4, limit - bits.length); i < t; i++) bits.push(0);
  while (bits.length % 8) bits.push(0);
  for (let i = 0; bits.length < limit; i++) put(i % 2 === 0 ? 0xEC : 0x11, 8);

  const dc = [];
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
    dc.push(b);
  }
  const blocks = [];
  let off = 0;
  for (let i = 0; i < spec.length; i += 3) {
    const n = spec[i], tot = spec[i + 1], dcn = spec[i + 2], ecn = tot - dcn;
    for (let k = 0; k < n; k++) {
      const d = dc.slice(off, off + dcn); off += dcn;
      blocks.push({ d: d, e: qrRsEc(d, ecn) });
    }
  }
  let maxD = 0, maxE = 0;
  for (const bl of blocks) { if (bl.d.length > maxD) maxD = bl.d.length; if (bl.e.length > maxE) maxE = bl.e.length; }
  const out = [];
  for (let i = 0; i < maxD; i++) for (const bl of blocks) if (i < bl.d.length) out.push(bl.d[i]);
  for (let i = 0; i < maxE; i++) for (const bl of blocks) if (i < bl.e.length) out.push(bl.e[i]);
  return { ver, data: out };
}

function qrFinder(m, row, col, n) {
  for (let r = -1; r <= 7; r++) {
    if (row + r < 0 || row + r >= n) continue;
    for (let c = -1; c <= 7; c++) {
      if (col + c < 0 || col + c >= n) continue;
      m[row + r][col + c] = ((r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
                             (c >= 0 && c <= 6 && (r === 0 || r === 6)) ||
                             (r >= 2 && r <= 4 && c >= 2 && c <= 4));
    }
  }
}
function qrAlignPatterns(m, ver, n) {
  const pos = QR_ALIGN[ver - 1];
  for (let i = 0; i < pos.length; i++) {
    for (let j = 0; j < pos.length; j++) {
      const row = pos[i], col = pos[j];
      if (m[row][col] !== null) continue;
      for (let r = -2; r <= 2; r++) for (let c = -2; c <= 2; c++) {
        m[row + r][col + c] = (r === -2 || r === 2 || c === -2 || c === 2 || (r === 0 && c === 0));
      }
    }
  }
}
function qrTiming(m, n) {
  for (let r = 8; r < n - 8; r++) if (m[r][6] === null) m[r][6] = (r % 2 === 0);
  for (let c = 8; c < n - 8; c++) if (m[6][c] === null) m[6][c] = (c % 2 === 0);
}
function qrTypeInfo(m, ecc, mask, test, n) {
  const ecBits = ecc === 'L' ? 1 : (ecc === 'M' ? 0 : (ecc === 'Q' ? 3 : 2));
  const data = (ecBits << 3) | mask;
  const bits = (qrBch(data, 0x537, 10) ^ 0x5412) >>> 0;
  for (let i = 0; i < 15; i++) {
    const mod = !test && (((bits >>> i) & 1) === 1);
    if (i < 6) m[i][8] = mod;
    else if (i < 8) m[i + 1][8] = mod;
    else m[n - 15 + i][8] = mod;
  }
  for (let i = 0; i < 15; i++) {
    const mod = !test && (((bits >>> i) & 1) === 1);
    if (i < 8) m[8][n - i - 1] = mod;
    else if (i < 9) m[8][15 - i] = mod;
    else m[8][15 - i - 1] = mod;
  }
  m[n - 8][8] = !test;
}
function qrTypeNumber(m, ver, test, n) {
  const bits = qrBch(ver, 0x1F25, 12);
  for (let i = 0; i < 18; i++) {
    const mod = !test && (((bits >>> i) & 1) === 1);
    m[Math.floor(i / 3)][i % 3 + n - 11] = mod;
  }
  for (let i = 0; i < 18; i++) {
    const mod = !test && (((bits >>> i) & 1) === 1);
    m[i % 3 + n - 11][Math.floor(i / 3)] = mod;
  }
}
function qrMaskFn(p, i, j) {
  switch (p) {
    case 0: return (i + j) % 2 === 0;
    case 1: return i % 2 === 0;
    case 2: return j % 3 === 0;
    case 3: return (i + j) % 3 === 0;
    case 4: return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0;
    case 5: return (i * j) % 2 + (i * j) % 3 === 0;
    case 6: return ((i * j) % 2 + (i * j) % 3) % 2 === 0;
    default: return ((i * j) % 3 + (i + j) % 2) % 2 === 0;
  }
}
function qrMapData(m, data, mask, n) {
  let inc = -1, row = n - 1, bitIndex = 7, byteIndex = 0;
  for (let col0 = n - 1; col0 > 0; col0 -= 2) {
    const col = col0 <= 6 ? col0 - 1 : col0;
    for (;;) {
      for (let c = col; c >= col - 1; c--) {
        if (c < 0) continue;
        if (m[row][c] === null) {
          let dark = false;
          if (byteIndex < data.length) dark = (((data[byteIndex] >>> bitIndex) & 1) === 1);
          if (qrMaskFn(mask, row, c)) dark = !dark;
          m[row][c] = dark;
          bitIndex--;
          if (bitIndex === -1) { byteIndex++; bitIndex = 7; }
        }
      }
      row += inc;
      if (row < 0 || row >= n) { row -= inc; inc = -inc; break; }
    }
  }
}
/* 掩码惩罚分：四条标准规则 */
function qrLostPoint(m, n) {
  let lp = 0;
  const container = new Array(n + 1).fill(0);
  for (let row = 0; row < n; row++) {
    let prev = m[row][0], len = 0;
    for (let col = 0; col < n; col++) {
      if (m[row][col] === prev) len++;
      else { if (len >= 5) container[len]++; len = 1; prev = m[row][col]; }
    }
    if (len >= 5) container[len]++;
  }
  for (let col = 0; col < n; col++) {
    let prev = m[0][col], len = 0;
    for (let row = 0; row < n; row++) {
      if (m[row][col] === prev) len++;
      else { if (len >= 5) container[len]++; len = 1; prev = m[row][col]; }
    }
    if (len >= 5) container[len]++;
  }
  for (let L = 5; L <= n; L++) lp += container[L] * (L - 2);

  for (let row = 0; row < n - 1; row++) {
    let col = 0;
    while (col < n - 1) {
      const tr = m[row][col + 1];
      if (tr !== m[row + 1][col + 1]) { col += 2; continue; }
      if (tr !== m[row][col]) { col++; continue; }
      if (tr !== m[row + 1][col]) { col++; continue; }
      lp += 3; col++;
    }
  }
  for (let row = 0; row < n; row++) {
    let col = 0;
    while (col < n - 10) {
      const r = m[row];
      if (!r[col + 1] && r[col + 4] && !r[col + 5] && r[col + 6] && !r[col + 9] &&
          ((r[col] && r[col + 2] && r[col + 3] && !r[col + 7] && !r[col + 8] && !r[col + 10]) ||
           (!r[col] && !r[col + 2] && !r[col + 3] && r[col + 7] && r[col + 8] && r[col + 10]))) lp += 40;
      col += r[col + 10] ? 2 : 1;
    }
  }
  for (let col = 0; col < n; col++) {
    let row = 0;
    while (row < n - 10) {
      if (!m[row + 1][col] && m[row + 4][col] && !m[row + 5][col] && m[row + 6][col] && !m[row + 9][col] &&
          ((m[row][col] && m[row + 2][col] && m[row + 3][col] && !m[row + 7][col] && !m[row + 8][col] && !m[row + 10][col]) ||
           (!m[row][col] && !m[row + 2][col] && !m[row + 3][col] && m[row + 7][col] && m[row + 8][col] && m[row + 10][col]))) lp += 40;
      row += m[row + 10][col] ? 2 : 1;
    }
  }
  let dark = 0;
  for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) if (m[i][j]) dark++;
  lp += Math.floor(Math.abs(dark / (n * n) * 100 - 50) / 5) * 10;
  return lp;
}
function qrMake(ver, data, ecc, test, mask) {
  const n = ver * 4 + 17;
  const m = [];
  for (let i = 0; i < n; i++) m.push(new Array(n).fill(null));
  qrFinder(m, 0, 0, n);
  qrFinder(m, n - 7, 0, n);
  qrFinder(m, 0, n - 7, n);
  qrAlignPatterns(m, ver, n);
  qrTiming(m, n);
  qrTypeInfo(m, ecc, mask, test, n);
  if (ver >= 7) qrTypeNumber(m, ver, test, n);
  qrMapData(m, data, mask, n);
  return m;
}
/* 返回 {size, rows:[('0'|'1')...]}；超出容量返回 null */
function qrMatrix(text, ecc) {
  const e = ecc === 'L' ? 'L' : 'M';
  const b = qrBuild(text, e);
  if (!b) return null;
  const n = b.ver * 4 + 17;
  let best = -1, bestScore = 0;
  for (let p = 0; p < 8; p++) {
    const sc = qrLostPoint(qrMake(b.ver, b.data, e, true, p), n);
    if (best < 0 || sc < bestScore) { best = p; bestScore = sc; }
  }
  const m = qrMake(b.ver, b.data, e, false, best);
  const rows = [];
  for (let i = 0; i < n; i++) {
    let s = '';
    for (let j = 0; j < n; j++) s += (m[i][j] ? '1' : '0');
    rows.push(s);
  }
  return { size: n, rows: rows };
}

/* ---- PNG 输出（灰度 8bit）：买家手机上长按图片即可存相册 ---- */
const QR_CRC_T = (function () {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); t[n] = c; }
  return t;
})();
function qrCrc32(buf) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) c = QR_CRC_T[(c ^ buf[i]) & 255] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}
function qrB64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
}
function qrPngChunk(type, data) {
  const n = data.length;
  const out = new Uint8Array(12 + n);
  out[0] = (n >>> 24) & 255; out[1] = (n >>> 16) & 255; out[2] = (n >>> 8) & 255; out[3] = n & 255;
  for (let i = 0; i < 4; i++) out[4 + i] = type.charCodeAt(i);
  out.set(data, 8);
  const c = qrCrc32(out.subarray(4, 8 + n));
  out[8 + n] = (c >>> 24) & 255; out[9 + n] = (c >>> 16) & 255; out[10 + n] = (c >>> 8) & 255; out[11 + n] = c & 255;
  return out;
}
async function qrPngDataUrl(text, opt) {
  const o = opt || {};
  const scale = o.scale || 4, quiet = o.quiet == null ? 4 : o.quiet;
  const r = qrMatrix(text, o.ecc || 'M');
  if (!r) return '';
  const n = r.size, dim = (n + quiet * 2) * scale;
  const raw = new Uint8Array(dim * (dim + 1));
  let p = 0;
  for (let y = 0; y < dim; y++) {
    raw[p++] = 0;                                  /* filter: None */
    const my = Math.floor(y / scale) - quiet;
    const line = (my >= 0 && my < n) ? r.rows[my] : '';
    for (let x = 0; x < dim; x++) {
      const mx = Math.floor(x / scale) - quiet;
      raw[p++] = (line && mx >= 0 && mx < n && line.charAt(mx) === '1') ? 0 : 255;
    }
  }
  const deflated = new Uint8Array(await new Response(
    new Blob([raw]).stream().pipeThrough(new CompressionStream('deflate'))
  ).arrayBuffer());
  const ihdr = new Uint8Array(13);
  ihdr[0] = (dim >>> 24) & 255; ihdr[1] = (dim >>> 16) & 255; ihdr[2] = (dim >>> 8) & 255; ihdr[3] = dim & 255;
  ihdr[4] = (dim >>> 24) & 255; ihdr[5] = (dim >>> 16) & 255; ihdr[6] = (dim >>> 8) & 255; ihdr[7] = dim & 255;
  ihdr[8] = 8; ihdr[9] = 0; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  const parts = [
    new Uint8Array([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    qrPngChunk('IHDR', ihdr),
    qrPngChunk('IDAT', deflated),
    qrPngChunk('IEND', new Uint8Array(0)),
  ];
  let total = 0;
  for (const x of parts) total += x.length;
  const all = new Uint8Array(total);
  let at = 0;
  for (const x of parts) { all.set(x, at); at += x.length; }
  return 'data:image/png;base64,' + qrB64(all);
}

/* ================= 一次性登记 token ================= */
/* 字母表去掉 0/O/1/I（口头报码、手打不会错）；32^8 ≈ 1.1 万亿 */
const REG_AB = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const REG_TTL_H = 24;                    /* 默认有效期 24 小时 */

function regCode() {
  const b = new Uint8Array(8);
  crypto.getRandomValues(b);
  let s = '';
  for (let i = 0; i < 8; i++) s += REG_AB[b[i] & 31];
  return s;
}
const regIso = ms => new Date(ms).toISOString();
function regTs(x) { const t = Date.parse(String(x || '')); return isNaN(t) ? 0 : t; }
function regNormCode(x) { return String(x || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12); }

/* 2026-11-09：邮箱校验（登记 / 买家自助 / 改邮箱 / 后台编辑共用一套）。
   原来四处都只做 /^[^\s@]+@[^\s@]+\.[^\s@]+$/，实测池里躺着 5 个 @qq.con、@qq.cpm，
   还有 1 个 @qq,com（逗号）—— 格式校验全放过，SMTP 必然失败，队列却照样标 sent，
   号主一封提醒都收不到、我们也不知道。返回空串 = 合法，否则返回直接给用户看的中文原因。 */
const EMAIL_TLD_TYPO = { con: 'com', cpm: 'com', ocm: 'com', comn: 'com', comm: 'com', cmo: 'com', cim: 'com', nte: 'net', ntei: 'net', orgg: 'org' };
function emailBad(x) {
  const s = String(x == null ? '' : x).trim();
  if (!s) return '请填写常用邮箱';
  if (s.length > 120) return '邮箱太长了，请检查一下';
  if (/[\s,，;；、]/.test(s)) return '邮箱里有多余的空格或逗号，请只填 name@example.com 这一串';
  const m = s.match(/^([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+)\.([A-Za-z]{2,8})$/);
  if (!m) return '邮箱格式不对，请填成 name@example.com 这样';
  if ((m[2] + '.' + m[3]).indexOf('..') >= 0) return '邮箱域名里有连续的句点，请检查一下';
  const tld = m[3].toLowerCase();
  if (EMAIL_TLD_TYPO[tld]) return '邮箱后缀好像写错了（' + tld + ' → ' + EMAIL_TLD_TYPO[tld] + '？），请确认后再提交';
  return '';
}

/* 客服口令（生成链接用）。KV 键 REG_TOKEN_PASS / D1 kv_misc.reg_token_pass，未配置 = 接口不开放 */
async function regPass() {
  let v = '';
  if (d1ok()) {
    try {
      const rows = await d1All('SELECT v FROM kv_misc WHERE k=?', ['reg_token_pass']);
      if (rows && rows.length) v = String(rows[0].v || '').trim();
    } catch (e) { console.error('读 reg_token_pass 失败:', e && e.message); }
  }
  if (!v) { try { v = cleanKV(await POOL.get('REG_TOKEN_PASS')); } catch (e) {} }
  return v;
}
/* 返回：null=不存在 / undefined=查询失败 / 行对象 */
async function regTokenGet(code) {
  if (!d1ok()) return undefined;
  const c = regNormCode(code);
  /* 2026-11-09：额度闸门 —— ≥95% 时先读 KV 镜像（1 次 KV 读，0 行 D1）。
     KV 里没有这条（老 token / 镜像当时没写上）仍要回 D1：宁可多烧几行，
     也不能让「链接明明有效却打不开」变成死路。 */
  if (await d1ReadBlocked()) {
    try {
      const kv = await POOL.get('regtok:' + c);
      if (kv) return JSON.parse(kv);
    } catch (e) { console.error('regtok 闸门读 KV 失败:', e && e.message); }
  }
  const rows = await d1All(
    'SELECT token,agent,plan,days,note,state,ctime,exp_at,used_at,uid,uname,phone,ledger_id,' +
    'kind,fix_exp,fix_ref,fix_name FROM reg_tokens WHERE token=?',
    [c]);
  if (rows === null) {
    /* 2026-11-08：D1「读」额度打满（UTC 日 500 万行，超额回 code 7500）时，
       这一行读不出来 → /api/r/state、/qrkey、/qrcheck、/submit 全部 503，
       买家拿着刚生成的链接连页面都打不开。而 reg_tokens 只有十几行、每次状态变更
       都会同步写 KV（regTokenNew / regTokenUse / regTokenUndo / regtoken_void），
       所以 KV 镜像天然可以当读兜底。
       ⚠️ 这里是「读失败」兜底，不是「读到空」：读到空仍然回 null（链接无效），
       只有连 KV 也没有时才回 undefined（页面提示系统忙）。 */
    try {
      const kv = await POOL.get('regtok:' + c);
      if (kv) return JSON.parse(kv);
    } catch (e) { console.error('regtok KV 兜底失败:', e && e.message); }
    return undefined;
  }
  if (!rows.length) return null;
  /* 顺手回填镜像：D1 真正读挂的那一刻，KV 里必须已经有这条 token。
     2026-11-09 修复：原来这里【每次读】都无条件 put，而买家登记页的 qrcheck 每 2 秒轮询一次
     /api/r/state —— 一次扫码 ≈ 60 次 KV 写。KV 免费档「写」只有 1000/天（与删/列共用），
     十几单登记就能打穿；打穿后 pool:hz 应急快照和 regtok: 镜像会一起写不进去，
     而 D1 读额度打满时买家链接正是靠这两样活着（11-08 事故的兜底就是它们）。
     改为「KV 里没有这个键才回填」：生成链接 regTokenNew、用掉 regTokenUse、作废
     regtoken_void 都已经写过镜像，读路径本来就是兜底，不需要每次读都重写一遍。 */
  try {
    const kv = await POOL.get('regtok:' + c);
    if (!kv) await POOL.put('regtok:' + c, JSON.stringify(rows[0]), { expirationTtl: 259200 });
  } catch (e) {}
  return rows[0];
}
/* reg_tokens 的 KV 镜像写（读路径见 regTokenGet）。写失败只告警，D1 仍是权威。 */
async function regTokenMirror(row, ttlSec) {
  if (!row || !row.token) return;
  const o = {
    token: String(row.token), agent: String(row.agent || ''), plan: String(row.plan || ''),
    days: Number(row.days) || 0, note: String(row.note || ''), state: String(row.state || 'unused'),
    ctime: row.ctime || '', exp_at: row.exp_at || '', used_at: row.used_at || null,
    uid: row.uid || null, uname: row.uname || null, phone: row.phone || null,
    ledger_id: row.ledger_id || null,
    /* 2026-11-10：链接类型也要进镜像 —— D1 读额度打满时买家全靠这份镜像提交，
       镜像里没有 kind，补登链接就会被当成新登记（白送一整个套餐）。 */
    kind: String(row.kind || 'new'), fix_exp: String(row.fix_exp || ''),
    fix_ref: String(row.fix_ref || ''),
    /* 原单手机号，买家页用它预填。缺了不影响判定，只是客户要多打一遍。 */
    fix_name: String(row.fix_name || ''),
  };
  const ttl = Math.max(60, Math.min(259200, Number(ttlSec) || 259200));
  try { await POOL.put('regtok:' + o.token, JSON.stringify(o), { expirationTtl: ttl }); } catch (e) {}
}
/* 有效状态：unused 且未过期 */
function regStateOf(row) {
  if (!row) return 'none';
  const st = String(row.state || 'unused');
  if (st === 'used') return 'used';
  if (st === 'void') return 'void';
  const exp = regTs(row.exp_at);
  if (exp && exp < Date.now()) return 'expired';
  return 'unused';
}
/* 2026-11-10 晚：手机号打码（138****8888）。补登链接的原单手机号原来是明文回给
   /api/r/state 的，页面还会自动填进输入框 —— 链接一旦被转发/截图，客户的号码就出去了。
   买家页只需要判断「这是不是我的号」，打码足够；真要登记还得自己打一遍，
   而「手机号必填 + 与网易 uid 一起进号池」这条口径没有任何变化。 */
function maskPhone(x) {
  const s = String(x || '').replace(/[^0-9]/g, '');
  if (!/^1\d{10}$/.test(s)) return '';
  return s.slice(0, 3) + '****' + s.slice(7);
}
/* ===== 2026-11-10：客服机器授权（reg_devices）=====
   背景：EXE 里的生成口令 REG_TOKEN_PASS 是硬编码的，EXE 外流就等于谁都能造链接。
   配额（200 条/天）只是止损。这里加一层「按机器授权」：
     客服电脑算出一个机器码 → 首次用时自动登记为 pending（24 小时宽限）→
     管理员在控制台放行（ok）→ 之后这台机器才继续能生成。
   老版 EXE 不带机器码字段：默认放行（否则上线瞬间所有客服全停），
   等新版都发出去、机器码都授权完，把 KV REG_REQUIRE_DEV 置 1 即可彻底关掉老版。 */
const REG_DEV_GRACE_MS = 24 * 3600 * 1000;

function regDevNorm(v) {
  return String(v || '').toUpperCase().replace(/[^0-9A-Z]/g, '').slice(0, 16);
}

/* 读一台机器的授权记录：D1 优先，读不到退 KV 镜像 dev:<码>。
   返回 {row, src} / null（D1 与 KV 都没有）/ undefined（D1 失败且 KV 没镜像）。 */
async function regDevGet(dev) {
  if (d1ok()) {
    const rows = await d1All(
      'SELECT dev,agent,quota,state,ctime,last_at FROM reg_devices WHERE dev=? LIMIT 1', [dev]);
    if (rows) return { row: rows[0] || null, src: 'd1' };
  }
  try {
    const raw = await POOL.get('dev:' + dev);
    if (raw) return { row: JSON.parse(raw), src: 'kv' };
  } catch (e) {}
  return undefined;
}

/* 返回 { ok, dev, quota, msg, legacy }。legacy=true 表示老版客户端（不带机器码）。
   2026-11-10 晚：加了第三个可选参数，让手机端（APK）复用同一套设备授权，但用**独立开关**
   和**独立文案**，两边的发版节奏互不影响：
     opt.requireKey  开关用的 KV 键名，默认 REG_REQUIRE_DEV（电脑版）；
                     APK 传 APK_REQUIRE_DEV —— 打开电脑闸门不会顺手把手机也锁死。
     opt.term        文案里的称呼，默认「电脑」。 */
async function regDevCheck(devRaw, agent, opt) {
  const o = opt || {};
  const kNeed = o.requireKey || 'REG_REQUIRE_DEV';
  const term = o.term || '电脑';
  const dev = regDevNorm(devRaw);
  if (!dev) {
    let need = '';
    try { need = cleanKV(await POOL.get(kNeed)); } catch (e) {}
    if (need === '1') {
      return { ok: false, dev: '', quota: 0,
        msg: '这台' + term + '上的软件版本太旧，已停止使用。请找管理员要新版软件。' };
    }
    return { ok: true, dev: '', quota: 0, legacy: true };
  }
  const g = await regDevGet(dev);
  if (g === undefined) {
    /* D1 读失败且 KV 没镜像：授权是钱的事，但此刻连记录都读不到，
       拒绝会让客服在额度打满时集体停摆。放行 + 留日志，等额度恢复再正常校验。 */
    console.error('regDevCheck 无法读取设备记录，临时放行:', dev);
    return { ok: true, dev: dev, quota: 0, degraded: true };
  }
  if (!g.row) {
    /* 第一次见到这台机器：登记 pending，给 24 小时宽限（老板在这段时间里授权）。 */
    const now = Date.now();
    const row = { dev: dev, agent: String(agent || ''), quota: 200, state: 'pending',
      note: '', ctime: regIso(now), last_at: regIso(now) };
    try {
      await d1Run('INSERT INTO reg_devices (dev,agent,quota,state,note,ctime,last_at) ' +
                  'VALUES (?,?,?,?,?,?,?) ON CONFLICT(dev) DO NOTHING',
                  [row.dev, row.agent, row.quota, row.state, row.note, row.ctime, row.last_at]);
    } catch (e) { console.error('登记新设备失败:', e && e.message); }
    try { await POOL.put('dev:' + dev, JSON.stringify(row)); } catch (e) {}
    return { ok: true, dev: dev, quota: 200, pending: true };
  }
  const st = String(g.row.state || 'pending');
  const quota = Math.max(1, Number(g.row.quota) || 200);
  if (st === 'ok') return { ok: true, dev: dev, quota: quota };
  if (st === 'hold') {
    return { ok: false, dev: dev, quota: 0, msg: '这台' + term + '的权限已被管理员停用，请联系管理员。' };
  }
  /* pending：看宽限期 */
  const born = regTs(g.row.ctime);
  if (born && (Date.now() - born) < REG_DEV_GRACE_MS) {
    return { ok: true, dev: dev, quota: quota, pending: true,
      grace_left_h: Math.max(1, Math.round((REG_DEV_GRACE_MS - (Date.now() - born)) / 3600000)) };
  }
  return { ok: false, dev: dev, quota: 0,
    msg: '这台' + term + '还没被授权。请把机器码 ' + dev + ' 发给管理员，授权后重新打开软件即可。' };
}

async function regDevTouch(dev, agent) {
  if (!dev) return;
  try {
    await d1Run('UPDATE reg_devices SET last_at=?, agent=CASE WHEN agent=\'\' THEN ? ELSE agent END WHERE dev=?',
                [regIso(Date.now()), String(agent || ''), dev]);
  } catch (e) {}
}

async function regTokenNew(agent, plan, days, note, hours, kind, fixExp, fixRef, fixName) {
  const code = regCode();
  const now = Date.now();
  const expAt = now + (hours || REG_TTL_H) * 3600 * 1000;
  /* 2026-11-10：kind 决定这一单算新登记 / 续费 / 补登。老调用方不传 → 默认 new（行为不变）。 */
  const k = (kind === 'fix' || kind === 'renew') ? kind : 'new';
  const ok = await d1Run(
    'INSERT INTO reg_tokens (token,agent,plan,days,note,state,ctime,exp_at,kind,fix_exp,fix_ref,fix_name) ' +
    'VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
    [code, String(agent || ''), String(plan || ''), Number(days) || 0, String(note || ''),
     'unused', regIso(now), regIso(expAt), k, String(fixExp || ''), String(fixRef || ''),
     String(fixName || '')]);
  if (ok) {
    /* 2026-11-08：新 token 立刻写一份 KV 镜像（TTL 跟链接有效期一致）。
       D1 读额度随时可能被别的查询打满，那时候买家只能靠这份镜像把链接打开。 */
    await regTokenMirror({ token: code, agent: agent, plan: plan, days: days, note: note,
      state: 'unused', ctime: regIso(now), exp_at: regIso(expAt),
      kind: k, fix_exp: String(fixExp || ''), fix_ref: String(fixRef || ''),
      fix_name: String(fixName || '') },
      ((hours || REG_TTL_H) * 3600) + 3600);
  }
  return ok ? { code: code, ctime: regIso(now), exp_at: regIso(expAt), kind: k } : null;
}
/* 原子消耗：返回 1=成功 / 0=已被用掉或不存在 / -1=D1 失败 */
async function regTokenUse(code, uid, uname, phone, ip, ua) {
  const c = regNormCode(code);
  const n = await d1Changes(
    "UPDATE reg_tokens SET state='used', used_at=?, uid=?, uname=?, phone=?, ip=?, ua=? " +
    "WHERE token=? AND state='unused'",
    [regIso(Date.now()), String(uid || ''), String(uname || ''), String(phone || ''),
     String(ip || '').slice(0, 40), String(ua || '').slice(0, 120), c]);
  if (n === 1) {
    try {
      const kv = await POOL.get('regtok:' + c);
      if (kv) {
        const o = JSON.parse(kv);
        o.state = 'used'; o.used_at = regIso(Date.now()); o.uid = String(uid || '');
        o.uname = String(uname || ''); o.phone = String(phone || '');
        await POOL.put('regtok:' + c, JSON.stringify(o), { expirationTtl: 259200 });
      }
    } catch (e) {}
  }
  return n;
}

/* ================= 网易云扫码（无状态会话，cookie 由浏览器回传） ================= */
/* 2026-11-12：扫码链 UA 从 iPhone 换成 Windows Chrome 网页版 —— st/platform/scanlogin
   的 chainId 后缀本来就是 _web_login_，伪造对象应是「网页扫码会话」，UA/cookie 要自洽。
   NC_UA 保留给 validateCookie/ncProfile 等其它网易出站用（改动最小化，不波及）。 */
const NC_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1';
const NC_WEB_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
const NC_BASE = 'https://music.163.com';
const NC_QTYPE = '3';                    /* 3 = 官方 st/platform 扫码；1 = 老接口（会被判环境异常） */
/* 2026-11-12 对症 -462「请完成验证操作」：社区实测（ts-dev-kits/netease-music、waylyrics 等）
   一致结论 —— 匿名请求不带 os/appver 基础 cookie 就会被风控判 -462；官方网页匿名访客
   下发的就是 os=pc; appver=2.9.7。ncHdr 拼接时若 bag 里已有同名键（网易 Set-Cookie 下发）
   则以 bag 为准，避免重复。 */

function ncSetCookies(r) {
  let out = [];
  try { if (typeof r.headers.getSetCookie === 'function') out = r.headers.getSetCookie() || []; } catch (e) {}
  if (!out.length) {
    try { const v = r.headers.get('set-cookie') || ''; if (v) out = v.split(/,(?=[^;=]+=)/); } catch (e) {}
  }
  return out;
}
function ncPickCookie(lines, name) {
  const re = new RegExp('(?:^|;\\s*)' + name + '=([^;]*)');
  for (const ln of lines) { const m = re.exec(ln || ''); if (m) return m[1]; }
  return '';
}
function ncAbsorb(bag, lines) {
  for (const ln of lines) {
    const seg = String(ln || '').split(';')[0] || '';
    const p = seg.indexOf('=');
    if (p <= 0) continue;
    const k = seg.slice(0, p).trim();
    if (k) bag[k] = seg.slice(p + 1).trim();
  }
  return bag;
}
/* 2026-11-12：基础 cookie（os=pc; appver=2.9.7）+ 网页 UA + Referer /login，
   只服务扫码三连（预热/unikey/client/login），validateCookie 等不走这里不受影响。 */
function ncHdr(bag) {
  const b = bag || {};
  const parts = [];
  if (!b.os) parts.push('os=pc');
  if (!b.appver) parts.push('appver=2.9.7');
  for (const k of Object.keys(b)) parts.push(k + '=' + b[k]);
  const h = { 'User-Agent': NC_WEB_UA, 'Referer': NC_BASE + '/login', 'Accept-Language': 'zh-CN,zh;q=0.9' };
  h['Cookie'] = parts.join('; ');
  return h;
}
function ncEncBag(bag) {
  try { return btoa(unescape(encodeURIComponent(JSON.stringify(bag)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  catch (e) { return ''; }
}
function ncDecBag(s) {
  if (!s) return {};
  try {
    let b = String(s).replace(/-/g, '+').replace(/_/g, '/');
    while (b.length % 4) b += '=';
    return JSON.parse(decodeURIComponent(escape(atob(b)))) || {};
  } catch (e) { return {}; }
}
/* 申请 unikey：预热首页拿 NMTID → weapi /weapi/login/qrcode/unikey（2026-11-12 改造）
   为什么换 weapi：老明文 /api/ 通道 + 裸 cookie 是 -462 风控的典型样本；官方网页走的就是
   weapi 加密通道，weapi() 复用 1224 行的实测实现。双通道保险：weapi 拿不到 unikey
   （非 JSON/异常/空回包）自动回退老明文通道，最坏情况等于改造前。 */
async function ncNewKey(bag) {
  try {
    const w = await fetch(NC_BASE + '/', { headers: ncHdr(bag), redirect: 'follow' });
    ncAbsorb(bag, ncSetCookies(w));
  } catch (e) { /* 预热失败不致命 */ }
  const csrf = bag.__csrf || bag.__csrf_token || '';
  try {
    const enc = await weapi({ type: NC_QTYPE, csrf_token: csrf });
    const r = await fetch(NC_BASE + '/weapi/login/qrcode/unikey', {
      method: 'POST',
      headers: Object.assign(ncHdr(bag), { 'Content-Type': 'application/x-www-form-urlencoded' }),
      body: 'params=' + encodeURIComponent(enc.params) + '&encSecKey=' + encodeURIComponent(enc.encSecKey),
    });
    const txt = await r.text();
    ncAbsorb(bag, ncSetCookies(r));
    let jw = null;
    try { jw = JSON.parse(txt); } catch (e) {}
    if (jw && jw.unikey) return { key: String(jw.unikey || '').trim(), code: jw.code, message: jw.message || '' };
    /* 没拿到 unikey → 落到下面的老通道重试 */
  } catch (e) { /* weapi 通道网络异常 → 老通道 */ }
  const r = await fetch(NC_BASE + '/api/login/qrcode/unikey?type=' + NC_QTYPE, {
    method: 'POST',
    headers: Object.assign(ncHdr(bag), { 'Content-Type': 'application/x-www-form-urlencoded' }),
    body: 'type=' + NC_QTYPE,
  });
  const txt = await r.text();
  ncAbsorb(bag, ncSetCookies(r));
  let j = null;
  try { j = JSON.parse(txt); } catch (e) {}
  if (!j) return { err: '网易返回的不是 JSON（可能被风控页拦了）' };
  return { key: String(j.unikey || '').trim(), code: j.code, message: j.message || '' };
}
async function ncPollOnce(bag, key) {
  const mk = (st, j, scs, txt) => ({
    status: st,
    code: (j && j.code) || 0,
    message: (j && j.message) || '',
    musicU: ncPickCookie(scs, 'MUSIC_U'),
    isJson: !!j,
    /* 2026-11-08：803 却拿不到 MUSIC_U 时（买家反馈「手机确认了、网页没反应」），
       把响应状态和 Set-Cookie 的**名字**带回去（只带名字不带值），方便定位是
       网易没下发、还是字段被改了。正常扫码用不到这两个字段。 */
    cookieNames: scs.map(x => String(x || '').split('=')[0].trim()).filter(Boolean),
    raw: txt.slice(0, 120),
  });
  /* 2026-11-12：weapi 优先（与官方网页同款加密通道 + os/appver cookie），异常或
     非 JSON 回退老明文 GET —— 双通道，最坏情况等于改造前。MUSIC_U 都从
     Set-Cookie 提取，weapi 的返回 code 体系（800/801/802/803）与明文一致。 */
  try {
    const csrf = bag.__csrf || bag.__csrf_token || '';
    const enc = await weapi({ key: key, type: NC_QTYPE, csrf_token: csrf });
    const rw = await fetch(NC_BASE + '/weapi/login/qrcode/client/login', {
      method: 'POST',
      headers: Object.assign(ncHdr(bag), { 'Content-Type': 'application/x-www-form-urlencoded' }),
      body: 'params=' + encodeURIComponent(enc.params) + '&encSecKey=' + encodeURIComponent(enc.encSecKey),
    });
    const scsW = ncSetCookies(rw);
    ncAbsorb(bag, scsW);
    const txtW = await rw.text();
    let jw = null;
    try { jw = JSON.parse(txtW); } catch (e) {}
    if (jw && jw.code) return mk(rw.status, jw, scsW, txtW);
    /* weapi 通道没给出 code → 落到老通道再试一次 */
  } catch (e) { /* weapi 通道网络异常 → 老通道 */ }
  const u = NC_BASE + '/api/login/qrcode/client/login?key=' + encodeURIComponent(key) + '&type=' + NC_QTYPE;
  const r = await fetch(u, { headers: ncHdr(bag) });
  const txt = await r.text();
  const scs = ncSetCookies(r);
  ncAbsorb(bag, scs);
  let j = null;
  try { j = JSON.parse(txt); } catch (e) {}
  return mk(r.status, j, scs, txt);
}
/* 官方扫码页地址：chainId 必须与申请/轮询用同一个 sDeviceId，否则 803 会变 8821 */
function ncScanUrl(key, dev) {
  return 'https://music.163.com/st/platform/scanlogin?codekey=' + encodeURIComponent(key) +
    '&chainId=v1_' + dev + '_web_login_' + Date.now() +
    '&hdw_device=web&hdw_appid=web&hitExp=1';
}

/* ================= 买家登记页（移动优先，暗色自适应） ================= */
const REG_HTML = `<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<title>账号登记</title>
<style>
:root{--bg:#f2f3f5;--card:#fff;--txt:#1a1a1a;--mut:#8b8b90;--line:#e8e8ec;--bd:#2f2f34;--pri:#ff2c55;--ok:#178a55}
@media (prefers-color-scheme:dark){:root{--bg:#101013;--card:#1c1c20;--txt:#f2f2f5;--mut:#8b8b93;--line:#2c2c32;--bd:#dcdce4;--ok:#3ddc97}}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{margin:0;background:var(--bg);color:var(--txt);font:16px/1.65 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif}
.wrap{max-width:480px;margin:0 auto;padding:18px 16px 44px}
h1{font-size:19px;margin:0 0 6px;font-weight:600}
.sub{color:var(--mut);font-size:13px;margin:0 0 16px;min-height:20px}
.card{background:var(--card);border-radius:16px;padding:18px 16px;margin-bottom:12px}
.qr{width:236px;max-width:66vw;margin:0 auto 10px;display:block;border-radius:10px;image-rendering:pixelated;background:#fff}
.qr.dim{opacity:.22;filter:blur(3px)}
.tip{text-align:center;font-size:13px;color:var(--mut);margin:0 0 12px;min-height:20px}
.row{display:flex;gap:8px}
button{flex:1;border:0;border-radius:11px;padding:12px 10px;font-size:15px;font-family:inherit;background:var(--line);color:var(--txt);cursor:pointer}
button.pri{background:var(--pri);color:#fff;font-weight:600}
button:disabled{opacity:.5}
/* 2026-11-08：标签原来是 13px 灰字，买家（尤其手机上）几乎看不见「要填什么」，
   改成 14px 加粗 + 正文色，和输入框拉开层次。 */
label{display:block;font-size:14px;font-weight:700;color:var(--txt);margin:16px 0 6px}
/* 2026-11-08：输入框边线原来用 --line(#e8e8ec)，白底上几乎看不见边界，
   买家不知道哪里能点。单独给一条更深的 --bd，按钮底色仍用 --line 不变。 */
input{width:100%;border:1px solid var(--bd);background:transparent;color:var(--txt);border-radius:11px;padding:11px 12px;font-size:15px;font-family:inherit;outline:none}
/* 2026-11-08：默认边线改成近黑（--bd），红色只留给「填错了」——聚焦不再是红色，
   改用一圈淡淡的描边表示「光标在这里」。 */
input:focus{border-color:var(--txt);box-shadow:0 0 0 3px rgba(128,128,128,.18)}
input.bad{border-color:#e0362b;box-shadow:0 0 0 3px rgba(224,54,43,.14)}
.hide{display:none!important}
.ok{color:var(--ok)}
.who{font-size:14px;background:rgba(23,138,85,.1);color:var(--ok);border-radius:10px;padding:10px 12px;word-break:break-all}
.steps{font-size:13px;color:var(--mut);line-height:1.85;margin:14px 0 0;padding:12px;background:var(--bg);border-radius:10px}
.steps b{color:var(--txt);font-weight:600}
/* 2026-11-08：给一段真实的分享范例，买家照着认「长这样就是对的了」 */
.ex{font-size:12.5px;color:var(--mut);background:var(--bg);border-left:3px solid var(--pri);border-radius:8px;padding:9px 11px;margin:8px 0 0;line-height:1.7;word-break:break-all;text-align:left}
.err{color:#d93025;font-size:14px;line-height:1.8}
.big{font-size:32px;text-align:center;margin:6px 0 2px}
/* 2026-11-08：电脑上打开时左右两栏（左二维码 / 右填表），省得来回滚；
   手机窄屏仍然上下排（.cols 退化成普通块）。 */
.cols>div{min-width:0}
.ph{padding:26px 16px;text-align:center;color:var(--mut);font-size:14px;line-height:1.9}
@media (min-width:780px){
  .wrap{max-width:920px}
  .cols{display:flex;gap:14px;align-items:flex-start}
  .cols>div{flex:1 1 0}
  .qr{width:300px;max-width:100%}
  .cols .steps{font-size:12.5px}
}
</style></head><body>
<div class="wrap">
  <h1>账号登记</h1>
  <p class="sub" id="sub">正在校验链接…</p>

  <div id="e-box" class="card hide"><div class="err" id="e-msg"></div></div>

  <div id="m-box" class="hide">
    <div class="cols">
      <div>
        <div class="card">
          <img id="qr" class="qr" alt="二维码">
          <p class="tip" id="qr-tip">正在生成二维码…</p>
          <div class="row">
            <button id="b-new">换一张</button>
            <button id="b-save" class="pri">保存到相册</button>
          </div>
        </div>
      </div>

      <div>
        <div class="card" id="f-box">
          <div class="who hide" id="who"></div>
          <label>歌曲链接（只能填单曲）</label>
          <input id="i-song" placeholder="APP：我的 → 顶上头像 → 歌曲 → 发布的歌" autocomplete="off">
          <p class="tip" style="text-align:left;margin:8px 0 0">怎么拿链接：网易云 APP → <b>我的</b> → 点顶上<b>头像</b> → <b>歌曲</b>标签页 → 我发布的歌 → 点那首歌的<b>分享</b> → 复制链接。</p>
          <p class="tip" style="text-align:left;margin:10px 0 0">分享出来长这样，整段粘进来就行：</p>
          <p class="ex">分享任素汐的单曲《我要你》: https://163cn.tv/bkyZ4bVK (来自@网易云音乐)</p>
          <p class="tip" style="text-align:left;margin:8px 0 0">只收<b>单曲</b>：专辑、歌单、电台、排行榜链接一律退回。原创 / 共创作品，共创人<b>不超过 2 人</b>。</p>
          <label>手机号（与网易音乐人绑定的手机号）</label>
          <input id="i-phone" inputmode="numeric" maxlength="11" placeholder="18888888888" autocomplete="off">
          <label>通知邮箱（掉线或需要验证时邮件通知）</label>
          <input id="i-email" inputmode="email" placeholder="123456@qq.com" autocomplete="off">
          <div class="row" style="margin-top:18px"><button id="b-sub" class="pri">完成登记</button></div>
          <p class="tip" id="sub-tip" style="margin:12px 0 0"></p>
        </div>
      </div>
    </div>
  </div>

  <div id="d-box" class="card hide">
    <div class="big ok">✓</div>
    <p class="tip ok" id="d-msg"></p>
    <p class="tip" id="d-uid" style="margin-top:10px"></p>
  </div>
</div>
<script>
(function(){
  var T = (location.pathname.split('/').pop() || '').toUpperCase();
  var E = function(id){ return document.getElementById(id); };
  var st = { key:'', dev:'', bag:'', mu:'', timer:0, tick:0, busy:false, done:false, scanned:false, weird:0, neg:0, dead:false, scanAt:0 };

  function show(id, on){ if (on) E(id).classList.remove('hide'); else E(id).classList.add('hide'); }
  function setTip(s){ E('qr-tip').textContent = s; }
  function fail(s){ show('e-box', true); E('e-msg').textContent = s; show('m-box', false); E('sub').textContent = ''; }
  /* 链接已经用掉过：不再当错误处理 —— 买家（或他的朋友）再点开时，
     看到的应该是「登记完成」，而不是一片红字吓人。 */
  function finished(s){
    show('m-box', false); show('e-box', false); show('d-box', true);
    E('d-msg').textContent = s || '登记完成，链接已失效。';
    E('sub').textContent = '';
  }

  function api(p, body){
    var o = body ? { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) } : {};
    return fetch(p, o).then(function(r){
      return r.text().then(function(t){
        var j = null; try { j = JSON.parse(t); } catch(e) {}
        if (!j) throw new Error('服务器返回异常（' + r.status + '）');
        return j;
      });
    });
  }

  var DEV_KEY = 'ncm_reg_dev';
  function getDev(){
    var d = '';
    try { d = localStorage.getItem(DEV_KEY) || ''; } catch(e) {}
    if (/^YD-[0-9a-f]{36}$/.test(d)) return d;
    var b = new Uint8Array(18); crypto.getRandomValues(b);
    var s = '';
    for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
    d = 'YD-' + s;
    try { localStorage.setItem(DEV_KEY, d); } catch(e) {}
    return d;
  }

  function step1(){
    api('/api/r/state?t=' + encodeURIComponent(T)).then(function(j){
      if (!j.ok) {
        if (j.used) { finished(j.message || '登记完成，链接已失效。'); return; }
        fail(j.message || '链接无效'); return;
      }
      /* 2026-11-10：按链接类型给不同说明 —— 补登是免费的，不能显示成「套餐：1月」，
         否则买家以为自己又买了一个月，回头找客服对账。 */
      var sub;
      if (j.kind === 'fix') {
        sub = '这是免费补登链接（原账号掉线补回，有效期不变' + (j.fix_exp ? '，仍到 ' + j.fix_exp : '') + '）'
            + (j.fix_name_m ? ' · 上次登记的手机号是 ' + j.fix_name_m + '，请在下面填完整' : '')
            + ' · 本链接 ' + j.left_h + ' 小时内有效（只能登记 1 个账号）';
      } else if (j.kind === 'renew') {
        sub = '这是续费链接（' + (j.planLabel || '套餐') + '，在原到期日基础上延长'
            + (j.fix_exp ? '，当前到期 ' + j.fix_exp : '') + '）· 本链接 ' + j.left_h + ' 小时内有效';
      } else {
        sub = (j.planLabel ? '套餐：' + j.planLabel + ' · ' : '') + '本链接 ' + j.left_h + ' 小时内有效（只能登记 1 个账号）';
      }
      E('sub').textContent = sub;
      /* 2026-11-10 晚：原来把原单手机号（j.fix_name）直接填进输入框。问题是这个接口
         谁拿到链接谁就能调 —— 链接被转发到群里或被人截图，客户号码就出去了。
         现在服务端只回打码版（j.fix_name_m），只用来让买家确认「是不是我的号」，
         号码本身要自己打一遍（手机号本来就是必填项，不影响判定）。 */
      show('m-box', true);
      st.dev = getDev();
      newQr();
    }).catch(function(e){ fail(e.message || '网络异常，请刷新重试'); });
  }

  var cdTimer = 0;
  /* 2026-11-08：等待期间「换一张」必须置灰。以前买家一边等一边点，码被换成新的，
     手机上确认的还是旧码，页面就永远等不到 803——表现就是「确认了没反应」。
     只有码真的废了（过期 / 800 / 风控连拒 / 出码失败）才解禁。 */
  function setNewBtn(on){
    try { E('b-new').disabled = !on; } catch(e) {}
  }
  function stopWait(msg){
    st.dead = true;
    clearInterval(cdTimer); clearTimeout(pTimer);
    E('qr').classList.add('dim');
    setTip(msg);
    setNewBtn(true);
  }
  function countdown(sec){
    clearInterval(cdTimer); st.tick = sec;
    cdTimer = setInterval(function(){
      st.tick--;
      if (st.tick <= 0) { stopWait('二维码已过期，点「换一张」'); return; }
      /* 2026-11-08：已扫码后不要让倒计时把「已扫码，请点确认」刷回「请扫码」，
         否则买家看到的就是「手机确认了、网页还是那句请扫码」。 */
      if (!st.mu && !st.scanned && !st.neg) setTip('使用网易云 APP 扫一扫（' + st.tick + 's）');
    }, 1000);
  }

  var pTimer = 0;
  function newQr(){
    if (st.busy || st.done) return;
    st.busy = true; st.dead = false; st.neg = 0; st.weird = 0;
    st.scanned = false; st.scanAt = 0;
    setNewBtn(false);
    try { E('b-save').disabled = false; } catch(e) {}
    setTip('正在生成二维码…');
    E('qr').classList.remove('dim');
    api('/api/r/qrkey?t=' + encodeURIComponent(T) + '&dev=' + encodeURIComponent(st.dev)).then(function(j){
      st.busy = false;
      if (!j.ok) { setTip(j.message || '出码失败，点「换一张」重试'); setNewBtn(true); return; }
      st.key = j.key; st.bag = j.bag;
      E('qr').src = j.img;
      countdown(j.ttl || 300);
      poll();
    }).catch(function(e){ st.busy = false; setTip('出码失败：' + (e.message || '网络异常')); setNewBtn(true); });
  }

  /* 2026-11-08：以前只有 801/802/803/800 四个分支，其它情况（网易回了非 JSON、
     803 却没带 MUSIC_U、链接刚好失效）全是「什么都不显示」——买家看到手机确认了、
     网页一动不动。现在任何异常都会把话说出来，并且不再空转。 */
  function poll(){
    clearTimeout(pTimer);
    if (st.done || st.dead || !st.key || st.mu) return;
    api('/api/r/qrcheck?t=' + encodeURIComponent(T) + '&key=' + encodeURIComponent(st.key) +
        '&dev=' + encodeURIComponent(st.dev) + '&bag=' + encodeURIComponent(st.bag)).then(function(j){
      if (st.done || st.dead) return;
      if (j.bag) st.bag = j.bag;
      if (!j.ok) {
        stopWait(j.message || '扫码状态读不到，点「换一张」重试');
        return;
      }
      if (j.code === 803) {
        if (j.mu) { got(j); return; }
        stopWait('扫码成功，但没拿到登录凭证。点「换一张」再扫一次' + (j.dbg ? '（' + j.dbg + '）' : ''));
        return;
      }
      if (j.code === 800) { stopWait('二维码已过期，点「换一张」'); return; }
      if (j.code === 802) {
        st.scanned = true; if (!st.scanAt) st.scanAt = Date.now();
        st.neg = 0; st.weird = 0;
        setTip('已扫码，请在手机上点「确认登录」');
      }
      else if (j.code === 801) {
        st.neg = 0; st.weird = 0;
        if (st.scanned) {
          var w = Date.now() - (st.scanAt || Date.now());
          setTip(w > 45000
            ? '还没收到确认：请回到手机上点「确认登录」，点了会自动跳转，不用刷新页面'
            : '已扫码，正在等你在手机上点「确认登录」');
        } else {
          setTip('使用网易云 APP 扫一扫（' + Math.max(0, st.tick) + 's）');
        }
      }
      else if (j.code < 0) {
        /* -462「请完成验证操作」：网易对**单次轮询**的风控回包，正常情况下隔一次
           就恢复成 801，所以前 3 次只降频重试、不废码。但实测也有整张码被卡死的
           情况（买家干等 1~2 分钟没动静）—— 连续 4 次（约 16 秒）都过不去就直接判死，
           把「换一张」解禁并说清怎么办，绝不让页面永远停在「校验中…」。
           2026-11-08：原来的写法是无限重试，买家看到的就是永远那一句提示。 */
        st.neg = (st.neg || 0) + 1;
        if (st.neg < 4) {
          if (st.neg === 1) {
            setTip(st.scanned ? '网易正在核对这次登录，稍等一下…（不用重新扫码）'
                              : '网易正在校验请求，稍等一下…（二维码不用换）');
          }
          pTimer = setTimeout(poll, 4000);
          return;
        }
        stopWait('这张二维码网易没放行（' + (j.message || ('code ' + j.code)) + '）。'
               + '点「换一张」重新扫码；如果还是这样，把手机换成流量（4G/5G）再扫，'
               + '或者直接找客服代取。');
        return;
      }
      else {
        st.weird = (st.weird || 0) + 1;
        if (st.weird < 3) { pTimer = setTimeout(poll, 2000); return; }   /* 偶发抖动先静默重试两次 */
        stopWait('扫码状态异常（code ' + j.code + (j.message ? '：' + j.message : '') + '），点「换一张」重试');
        return;
      }
      pTimer = setTimeout(poll, 2000);
    }).catch(function(){ if (st.dead || st.done) return; setTip('网络抖动，正在重试…'); pTimer = setTimeout(poll, 3000); });
  }

  function got(j){
    st.mu = j.mu; st.scanned = true; st.dead = true;
    clearInterval(cdTimer); clearTimeout(pTimer);
    E('qr').classList.add('dim');
    setTip('扫码成功');
    /* 2026-11-08：已经登录成功了，这张码再存也没用（还会被误当成新码去扫），
       所以「保存到相册」一起置灰，和「换一张」保持一致。 */
    try { E('b-save').disabled = true; } catch(e) {}
    E('who').textContent = '已识别账号：' + (j.nick || '网易云账号') + (j.uid ? '（uid ' + j.uid + '）' : '');
    /* 2026-11-11：表单改成进页面就全展示（买家扫完就关浏览器，以为登记完了），
       扫码成功只要把「已识别账号」这条绿条补上即可，不用再切 f-box。 */
    show('who', true);
    // 手机窄屏才滚（电脑上是左右两栏，滚一下反而把二维码滚走了）
    if (window.innerWidth < 780) {
      try { E('f-box').scrollIntoView({ behavior:'smooth', block:'start' }); } catch(e) {}
    }
  }

  E('b-new').onclick = function(){ if (!st.done && !st.mu) newQr(); };
  E('b-save').onclick = function(){
    var im = E('qr');
    if (!im.src || im.src.indexOf('data:') !== 0) return;
    var a = document.createElement('a');
    a.href = im.src; a.download = 'qr.png';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTip('已保存（也可以直接长按二维码存图）');
  };

  /* 2026-11-08：填错才标红。默认边线是近黑，红色专门表示「这个框要改」，
     用户一编辑就自动去掉红边，不用等他再点一次提交。 */
  var FIELDS = ['i-song', 'i-phone', 'i-email'];
  function clearBad(){
    for (var i = 0; i < FIELDS.length; i++) { var el = E(FIELDS[i]); if (el) el.classList.remove('bad'); }
  }
  function markBad(id){ var el = E(id); if (el) el.classList.add('bad'); }
  for (var fi = 0; fi < FIELDS.length; fi += 1) {
    (function(id){
      var el = E(id);
      if (!el) return;
      el.addEventListener('input', function(){ el.classList.remove('bad'); });
    })(FIELDS[fi]);
  }

  E('b-sub').onclick = function(){
    if (st.busy || st.done) return;
    if (!st.mu) { E('sub-tip').textContent = '还没扫码：请先用网易云 APP 扫页面上的二维码，并在手机上点「确认登录」，再回来点「完成登记」'; return; }
    var song = E('i-song').value.trim();
    var phone = E('i-phone').value.replace(/[^0-9]/g, '');
    var email = E('i-email').value.trim();
    clearBad();
    if (!song) { markBad('i-song'); E('sub-tip').textContent = '请填歌曲链接'; return; }
    /* 2026-11-08：只收单曲。合集链接（专辑/歌单/电台/排行榜/MV）一律当场退回，
       服务端 resolveSong 还会再查一次，这里先拦是为了让买家立刻知道该改什么。 */
    if (/(playlist|album|radio|program|toplist|djradio|artist|mv)/i.test(song)) {
      markBad('i-song');
      E('sub-tip').textContent = '只收单曲链接：专辑 / 歌单 / 电台 / 排行榜都不能登记。请在 APP 里打开那首歌，再点「分享 → 复制链接」';
      return;
    }
    if (!/(music\\.163\\.com|163cn\\.tv|163cn\\.com)/i.test(song)) {
      markBad('i-song');
      E('sub-tip').textContent = '这不像网易云的单曲分享链接，请用 APP 里那首歌的「分享 → 复制链接」';
      return;
    }
    /* 2026-11-10：手机号改必填（原来是选填）。它是客户掉了号之后找回原单的唯一凭据
       （另一个抓手是网易 UID，但换号就没了），空着等于这一单以后没法证明是谁的，
       补登时既认不出人、到期提醒也没人收。 */
    if (!phone) { markBad('i-phone'); E('sub-tip').textContent = '请填手机号：登录网易云用的那个 11 位手机号'; return; }
    if (!/^1\\d{10}$/.test(phone)) { markBad('i-phone'); E('sub-tip').textContent = '手机号要 11 位、以 1 开头，请检查一下'; return; }
    if (!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)) { markBad('i-email'); E('sub-tip').textContent = '请填一个能收到信的邮箱'; return; }
    st.busy = true;
    E('b-sub').disabled = true;
    E('sub-tip').textContent = '正在登记，请不要关页面…';
    api('/api/r/submit', { t: T, mu: st.mu, phone: phone, link: song, email: email }).then(function(j){
      st.busy = false;
      if (!j.ok) {
        E('b-sub').disabled = false;
        var m = j.message || '登记失败';
        /* 服务端退回的「不是单曲 / 链接不对」也算填错，照样标红那个框 */
        if (m.indexOf('单曲') >= 0 || m.indexOf('链接') >= 0) markBad('i-song');
        E('sub-tip').textContent = m;
        return;
      }
      st.done = true;
      show('m-box', false); show('d-box', true);
      E('d-msg').textContent = j.message || '登记成功';
      /* 2026-11-10：把网易号 UID 直接告诉客户 —— 客户基本不知道自己的 UID 是哪个数字，
         而补号/查单都要它。登记成功这一刻是唯一能「当面交付」的时机。 */
      if (j.uid) {
        E('d-uid').textContent = '你的网易号 UID：' + j.uid + '（截图存一下；以后号掉线找客服补号，报这个最快）';
      }
    }).catch(function(e){ st.busy = false; E('b-sub').disabled = false; E('sub-tip').textContent = e.message || '网络异常'; });
  };

  if (!/^[A-Z0-9]{6,12}$/.test(T)) { fail('链接不完整，请复制客服发的完整链接'); return; }
  step1();
})();
</script>
</body></html>`;

/* 网易云账号资料（803 之后取昵称，只调用一次） */
async function ncProfile(mu) {
  try {
    const r = await fetch(NC_BASE + '/api/nuser/account/get',
      { headers: { 'User-Agent': NC_UA, 'Referer': NC_BASE + '/', 'Cookie': 'MUSIC_U=' + mu } });
    const j = await r.json();
    if (j && j.profile) return { uid: String(j.profile.userId || ''), nick: String(j.profile.nickname || '') };
  } catch (e) { /* 拿不到昵称不影响登记 */ }
  return null;
}
/* 回滚 token（抢占后登记失败才用） */
async function regTokenUndo(code) {
  const c = regNormCode(code);
  const n = await d1Changes(
    "UPDATE reg_tokens SET state='unused', used_at=NULL, uid='', uname='', phone='' " +
    "WHERE token=? AND state='used'", [c]);
  if (n === 1) {
    try {
      const kv = await POOL.get('regtok:' + c);
      if (kv) {
        const o = JSON.parse(kv);
        o.state = 'unused'; o.used_at = null; o.uid = null; o.uname = null; o.phone = null;
        await POOL.put('regtok:' + c, JSON.stringify(o), { expirationTtl: 259200 });
      }
    } catch (e) {}
  }
  return n;
}

async function handle(request) {
    const url = new URL(request.url);
    // 2026-10-25：网页口令统一闸门（KV PAGE_PASS，未配置则不启用）。只拦网页，/api/* 一律放行 ——
    // APK/EXE 直接调接口，加口令会让软件全线失效。
    if (PAGE_ROUTES.has(url.pathname)) {
      const gate = await pageGate(request, url);
      if (gate) return gate;
    }
    if (url.pathname === '/' || url.pathname === '/index.html') {
      // 2026-10-22：页面里「号池上限 N 人」原来硬编码 200、再靠字符串替换成 KV 里的值 ——
      // 文案一改就静默失效。改成模板占位符 __POOL_LIMIT__，只替换占位符，文案随便改都不影响。
      let lim = 1200;
      try { lim = parseInt(cleanKV(await POOL.get('POOL_LIMIT_G1')), 10) || 1200; } catch (e) {}
      return new Response(INDEX_HTML.replace('__POOL_LIMIT__', String(lim)),
        { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    // ---- 群主管理后台（只读）：ADMIN_PASS 独立口令，NOT 群口令 ----
    if (url.pathname === '/admin' && request.method === 'GET') {
      return new Response(ADMIN_HTML, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    // ---- 手动触发 snap650 补采（2026-10-24）：口令同 ASSIGN_PASS，只接受 POST ----
    // 日常由 CF 原生 cron 走 scheduled 自动触发；这个入口只用于人工补跑和排障（查 cron 有没有生效）。
    if (url.pathname === '/api/cron_snap') {
      const c0 = await cfg();
      if (!c0.assignPass) return json({ message: '尚未配置 ASSIGN_PASS，该接口不开放' }, 503);
      if (request.method !== 'POST') return json({ message: '请用 POST' }, 405);
      if ((url.searchParams.get('pass') || '') !== c0.assignPass) return json({ message: '口令错误' }, 403);
      return json(await dispatchSnap650(url.searchParams.get('pool') || 'all'));
    }
    // ---- D1 额度水位（2026-11-09）----
    // 闸门读的是 KV qgt:d1（{p:百分比, t:探测时间}）。平时由 scheduled / /api/assign 的探针刷新；
    // 这个入口用于：①本地跑完 tmp/cf_quota.py 后立刻把水位写进去 ②怀疑探针哑了时手工核对。
    // 不传 p 就跑一次真探针（force，跳过节流）；传了 p 直接落值（自己算好百分比时用）。
    if (url.pathname === '/api/quota_report') {
      const cq = await cfg();
      if (!cq.assignPass) return json({ message: '尚未配置 ASSIGN_PASS，该接口不开放' }, 503);
      if (request.method !== 'POST') return json({ message: '请用 POST' }, 405);
      if ((url.searchParams.get('pass') || '') !== cq.assignPass) return json({ message: '口令错误' }, 403);
      let bq = null;
      try { bq = await request.json(); } catch (e) {}
      const pIn = (bq && bq.p != null) ? Number(bq.p) : NaN;
      if (isFinite(pIn)) {
        const p = Math.max(0, Math.min(999, pIn));
        // 手动落值：KV（跨 colo 全局）+ Cache API（同 colo 立即可读）双写
        try {
          await POOL.put(QGATE_KEY, JSON.stringify({ p: p, t: Date.now(), src: 'manual' }),
                         { expirationTtl: 7200 });
        } catch (e) {}
        await caPut(QGATE_KEY, JSON.stringify({ p: p, t: Date.now(), src: 'manual' }), 7200);
        _qgPct = p; _qgAt = Date.now();
        return json({ ok: true, pct: p, src: 'manual', hot: p >= QGATE_HOT });
      }
      const rq = await d1QuotaProbe(true);
      return json(Object.assign({ ok: !rq.skip, hot: Number(rq.pct) >= QGATE_HOT }, rq));
    }
    // 本地后台网页（号池管理网页.html）跨域调用本接口：放开 CORS 并处理预检
    // ---- 客服名单 + 套餐档位（2026-10-27 新增）----
    // APK / EXE 每次登记前拉一次；名单改在控制台「客服名单」里，改完客户端下次拉就变，不用重发软件。
    // 不含任何账号信息，故不鉴权（登记接口本来就是公开的）。
    if (url.pathname === '/api/agents') {
      const CORS = { 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' };
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: {
        'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type' } });
      if (request.method !== 'GET') return json({ message: '请用 GET' }, 405, CORS);
      const rc = await regCfg();
      return json({ ok: true, agents: rc.agents, plans: rc.plans, at: new Date().toISOString() }, 200, CORS);
    }
    if (url.pathname === '/api/pool' && request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      } });
    }
    if (url.pathname === '/api/pool' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      const c = await cfg();
      /* 2026-11-11 v2.12：号池【查看】口令放宽 —— ADMIN_PASS / CONSOLE_PASS / CONSOLE_RO_PASS
         任一可读。背景：APK 号池页输满权/只读码报「管理密码错误」，因为这里原先只认 ADMIN_PASS，
         而同一批口令在 /console 又是能登录看数据的，口径分裂。这是纯读接口，放宽不放大写权限；
         写操作（/api/admin/entry 等）维持只认 ADMIN_PASS 不变。 */
      const noPassAtAll = !c.adminPass && !c.consolePass && !c.consoleRoPass;
      if (noPassAtAll) return json({ message: '尚未设置管理密码：请在 Cloudflare KV 中添加 ADMIN_PASS 键（任意长随机字符串）' }, 503, CORS);
      const poolViewOk = !!body.pass && (body.pass === c.adminPass || body.pass === c.consolePass || body.pass === c.consoleRoPass);
      if (!poolViewOk) return json({ message: '管理密码错误' }, 403, CORS);
      /* 2026-11-09：原来每次刷新管理页都跑一遍 pruneExpired()（重建全池 + 到期号逐个写 KV +
         可能刷一次 pool 快照）。而「到期降级公益号」早已挪进每日 cron（scheduled 里
         ctx.waitUntil(pruneExpired())，2026-10-29 的事），这里再跑等于每刷新一次多一份写副作用。
         改成纯读：管理后台怎么刷都不再产生任何写入。 */
      const master = await mergePool();
      // 只回展示字段，绝不下发 ck（cookie）等敏感数据
      const entries = master.map(e => ({
        name: e.name || '', uid: e.uid != null ? String(e.uid) : '',
        song: e.song != null ? String(e.song) : '', added: e.added || '',
        email: e.email || '', phone: e.phone || '', noListen: !!e.noListen, exp: e.exp || '',
        pub: !!e.pub,
      }));
      const stats = {
        total: entries.length,
        withMail: entries.filter(e => e.email).length,
        noMail: entries.filter(e => !e.email).length,
        noListen: entries.filter(e => e.noListen).length,
        public: entries.filter(e => e.pub || !e.song).length,
        expiring: entries.filter(isSoonExpired).length,
        manual: entries.filter(e => String(e.name).indexOf('qr:') === 0 || String(e.name).indexOf('manual:') === 0).length,
        limit: c.poolLimitG1,
        remain: Math.max(0, c.poolLimitG1 - entries.length),
      };
      return json({ ok: true, stats: stats, entries: entries }, 200, CORS);
    }
    // ---- 跨群互听歌单（2026-10-20）：只回"可以被听到的歌曲 id"，绝不回任何账号/cookie 信息。
    //      互助群与定制群互相拉这份列表，把两边的歌并成一个歌池，但两个 KV 号池独立、人数各算各的。
    //      口令走 KV 键 PEER_PASS（两边设同一个值）；未设置则该接口不开放。
    if (url.pathname === '/api/songs' && request.method === 'GET') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      // 2026-10-26：口令优先 PEER_KEY（独立 32 位随机，两群同一个值），未配置才回退旧的 PEER_PASS。
      const c = await cfg();
      if (!(await peerPassOk(url.searchParams.get('pass')))) {
        const anyKey = (await peerKey()) || cleanKV(await POOL.get('PEER_PASS'));
        if (!anyKey) return json({ message: '未开启跨群互听：请在 KV 添加 PEER_KEY 键' }, 503, CORS);
        return json({ message: '口令错误' }, 403, CORS);
      }
      // 2026-10-22：这里原来调 pruneExpired()（= 全量重建 + 删键 + 写 master + 推 12 个 Secret）。
      // 但这是「取歌单」这种只读高频接口，不该带写副作用。改为单条 SELECT DISTINCT，
      // 过期号由 /api/pool（管理后台）或 resync 之类管理动作去清。
      let songs;
      // 2026-11-01：pub=1 的公益号登记的歌不再对外提供（"自己的歌不需要别人听"），
      // 否则对端群仍会把它拉进歌池、平白分走播放次数。
      const rows = d1ok()
        ? await d1All("SELECT DISTINCT song FROM accounts WHERE pool=? AND song<>'' AND pub=0 ORDER BY song", [POOL_NAME])
        : null;
      if (rows) songs = rows.map(r => String(r.song)).filter(Boolean);
      else songs = (await mergePool()).filter(e => !e.pub).map(e => String(e.song || '')).filter(Boolean);
      songs = [...new Set(songs)].sort();
      return json({ ok: true, count: songs.length, songs: songs }, 200, CORS);
    }
    // ---- D1 分配接口（2026-10-22 新增）：run.py 直接问「本班跑哪些号、每号听什么」----
    if ((url.pathname === '/api/assign' || url.pathname === '/api/pool_stat') && request.method === 'GET') {
      const c = await cfg();
      const pass = url.searchParams.get('pass') || '';
      // 2026-10-22 安全修正：本接口会回明文 CK，绝不能再用「发给全体成员的群口令」鉴权
      //（否则任何成员循环 job=0..N 就能拖走全池 MUSIC_U）。只认独立键 ASSIGN_PASS；
      // 管理密码 ADMIN_PASS 仍放行，方便手工排错。
      if (!c.assignPass) return json({ ok: false, message: '未配置分配口令（KV 键 ASSIGN_PASS），D1 分配接口未开放' }, 503);
      const okPass = pass === c.assignPass;
      const okAdmin = c.adminPass && pass === c.adminPass;
      if (!okPass && !okAdmin) return json({ ok: false, message: '口令错误' }, 403);
      if (!d1ok()) return json({ ok: false, message: 'D1 未绑定' }, 503);
      const t0 = Date.now();
      // 2026-11-09：relay 每片开工都会过这里 → 顺手探一次 D1 额度水位（10 分钟节流，失败静默）。
      // 只有这里能拿到「一轮中间」的水位；仅靠 scheduled（每小时）事故期间来不及降级。
      // 2026-11-10：顺带重放「登记了但没写进 D1」的补偿队列（5 分钟节流，表空时几乎零成本）。
      try {
        if (globalThis.CTX && globalThis.CTX.waitUntil) {
          globalThis.CTX.waitUntil(d1QuotaProbe().catch(() => {}));
          globalThis.CTX.waitUntil(replayFixups().catch(() => {}));
        }
      } catch (e) {}
      if (url.pathname === '/api/pool_stat') {
        const plan = await buildPlan(url.searchParams.get('day'));
        if (!plan.ok) return json({ ok: false, message: plan.msg }, 503);
        const own = plan.plans.filter(x => x.pool === POOL_NAME);
        const mine = own.length;
        const idleN = (plan.idle || []).filter(x => x.pool === POOL_NAME).length;
        // 2026-11-09：落「当轮应跑名单」快照，供 /api/coverage 与控制台按同一口径比对。
        // plan job 每轮调一次本接口 → 首轮写、之后的补跑不覆盖（见 planSnapPut）。
        let snapWrote = 0;
        try {
          snapWrote = (await planSnapPut(plan.day, POOL_NAME, own.map(x => String(x.uid)), plan.src || 'd1')) ? 1 : 0;
        } catch (e) {}
        // 2026-11-09：带上 accel（slots/perDay/per/max/capped）。原来只回 m/l/p，
        // 文档让「进度不对就查 capped」根本查不到 —— 派单是否被 PER_CAP 等比稀释只能靠猜。
        return json({ ok: true, pool: POOL_NAME, day: plan.day, m: plan.m, l: plan.l,
                      p: plan.p, m_pool: mine, idle: idleN, src: plan.src || 'd1',
                      accel: plan.accel || null, snap: snapWrote, ms: Date.now() - t0 });
      }
      const job = Math.max(0, parseInt(url.searchParams.get('job') || '0', 10) || 0);
      const jobs = Math.max(1, parseInt(url.searchParams.get('jobs') || '1', 10) || 1);
      if (job >= jobs) return json({ ok: false, message: 'job 超出范围' }, 400);
      const plan = await buildPlan(url.searchParams.get('day'));
      if (!plan.ok) return json({ ok: false, message: plan.msg }, 503);
      const ownPool = plan.plans.filter(x => x.pool === POOL_NAME);
      // 2026-11-06：本群 0 个号、全池却有号 —— 要么本群池真空了，要么 pool 字段对不上。
      // 以前这里静默返回 0 个号，run.py 分不清「本群真没号」和「接口这次出错」。
      if (!ownPool.length && plan.m > 0) {
        console.error('[assign] 本群 0 个号，但全池有 ' + plan.m + ' 个（pool=' + POOL_NAME + ', src=' + (plan.src || 'd1') + '）');
      }
      // 2026-10-29：按 uid 哈希桶分片（sliceBucket），不再用数组下标，池变动不漂移。
      const mine = ownPool.filter(x => sliceBucket(x.uid, jobs, plan.day) === job);
      // 只收不听的号（no_listen）以前完全不进 assign → 不签到、不查工作台、不验活、死了也不报。
      // 现在按同一套 sliceBucket 分片下发给各片，run.py 只让它们查工作台/上报，不参与播放。
      const ownIdle = (plan.idle || []).filter(x => x.pool === POOL_NAME);
      const mineIdle = ownIdle.filter(x => sliceBucket(x.uid, jobs, plan.day) === job);
      // D1 主路径为省传输没查 ck/email，这里按本片那几个号补一次；KV 兜底路径自带 ck，不会触发。
      const meta = {};
      const need = mine.concat(mineIdle).filter(x => !x.ck);
      // 2026-10-24 修复：D1 单条 SQL 最多 100 个绑定参数（实测 101 个即报
      // "too many SQL variables"）。snap650 用 jobs=1 拉全池（200+ 号）时，
      // 这里拼出 220+ 个 ? → 整条查询失败 → 补不到 ck → 接口返回 0 个号，
      // 上午 10:00 的 650 补采从上线起就没成功过。改为每批 90 个 uid 分次查。
      // 正常播放路径 jobs=250（每片 1-2 个号）仍只跑一次循环，行为不变。
      for (let i = 0; i < need.length; i += 90) {
        const uids = need.slice(i, i + 90).map(x => x.uid);
        const ph = uids.map(() => '?').join(',');
        const rs = await d1All('SELECT uid,name,ck,email FROM accounts WHERE pool=? AND uid IN (' + ph + ')',
                               [POOL_NAME].concat(uids));
        // 2026-11-06 关键修复：这次补查失败（D1 额度耗尽 / 网络中断）时 d1All 返回 null，
        // 原来的 `(rs || [])` 把它当成「这些号没有 CK」→ 下面 filter(x => x.ck) 会把整片号
        // 全部滤掉 → 接口返回 0 个号 → run.py 判定「没分到名单」→ 回退仓库里的 10 月老名单
        // ⇒ 11-06 那次「主群 127 号双播 / 137 号零播、定制群 16 号双播 / 23 号零播」的真实起点。
        if (!rs) return json({ ok: false, message: 'D1 查询失败（本片 CK 补查），请稍后重试' }, 503);
        for (const r of rs) meta[String(r.uid)] = r;
      }
      // 2026-11-11：公益号（pub=1）的歌一律不得出现在任何号的 plays 里 —— 号主诉求是
      // 「公益号只负责听别人的，自己的歌不能被听」。buildPlanFrom 的 songs 已经按 !pub 过滤，
      // 这里再加一道出口闸：只要某个 pub 号的 song 混进了 plays（老计划、KV 兜底、以后谁改错
      // 过滤条件），就在这一层剔除。这是下发播放任务的唯一出口，挡在这里 = 全链路兜住。
      // 注意必须把 idle（只收不听 / 失效）也并进来：pub 且 no_listen 的号不进 plans，只在 idle 里。
      const pubSongs = new Set((plan.plans || []).concat(plan.idle || [])
        .filter(x => x.pub && x.song).map(x => String(x.song)));
      const pack = x => {
        const m = x.ck ? x : (meta[x.uid] || {});
        const plays = pubSongs.size
          ? (x.plays || []).filter(s => !pubSongs.has(String(s)))
          : (x.plays || []);
        return { uid: x.uid, name: m.name || x.name || '', ck: m.ck || x.ck || '',
                 email: m.email || x.email || '', song: x.song || '', plays: plays,
                 // 2026-11-01：公益号标记（make_accounts.py 据此跳过签到/发笔记）
                 pub: x.pub ? 1 : 0 };
      };
      // 只返回真正带 CK 的号（历史占位行 CK 为空，下发过去也只会白跑一次验活）
      const accounts = mine.map(pack).filter(x => x.ck);
      const idle = mineIdle.map(pack).filter(x => x.ck);
      return json({ ok: true, pool: POOL_NAME, day: plan.day, m: plan.m, l: plan.l, p: plan.p,
                    m_pool: ownPool.length, jobs: jobs, job: job, src: plan.src || 'd1',
                    accounts: accounts, idle: idle, ms: Date.now() - t0 });
    }
    // ---- D1 全量对齐（管理员）：把 KV 当前权威数据整表同步到 D1 ----
    if (url.pathname === '/api/d1_sync' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      if (!c.adminPass || body.pass !== c.adminPass) return json({ message: '管理密码错误' }, 403);
      if (!d1ok()) return json({ message: 'D1 未绑定' }, 503);
      const master = await mergePoolKV();   // 必须读 KV 原文，否则等于 D1 对齐 D1
      let ok = 0, skip = 0, fail = 0;
      for (const e of master) {
        if (e.uid == null || String(e.uid) === '') { skip++; continue; }
        if (await d1Upsert(e)) ok++; else fail++;
      }
      const live = new Set(master.filter(e => e.uid != null).map(e => String(e.uid)));
      const rows = await d1All('SELECT uid FROM accounts WHERE pool=?', [POOL_NAME]);
      // 2026-11-06：读失败时 rows 为 null，绝不能当成「D1 是空的」继续算差集。
      if (!rows) return json({ message: 'D1 查询失败（accounts 读不到），已中止对齐' }, 503);
      // 'name:xxx' 是「没有 uid 的老条目」的占位主键，不在 live 里但绝不能删。
      const gone = rows.filter(r => !String(r.uid).startsWith('name:') && !live.has(String(r.uid)));
      await Promise.all(gone.map(r => d1Run('DELETE FROM accounts WHERE pool=? AND uid=?', [POOL_NAME, String(r.uid)])));
      try { await refreshPoolSnap(true); } catch (e) {}   // D1 全表刚被重写 → 同步刷新应急快照（force）
      return json({ ok: true, pool: POOL_NAME, kv: master.length, synced: ok, skipped: skip,
                    failed: fail, removed: gone.length });
    }
    // ---- 管理端账号维护（本地管理页专用）：删除 / 修改（CK、邮箱、歌曲、有效期、暂停互听）----
    if (url.pathname === '/api/admin/entry' && request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      } });
    }
    if (url.pathname === '/api/admin/entry' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      const c = await cfg();
      if (!c.adminPass) return json({ message: '尚未设置管理密码' }, 503, CORS);
      if (!body.pass || body.pass !== c.adminPass) return json({ message: '管理密码错误' }, 403, CORS);
      // 2026-10-22：编辑逻辑抽成 applyEntryEdit，供本路由与控制台编辑接口 /api/console/entry 共用（行为不变）
      const _rAe = await applyEntryEdit(body);
      // 2026-11-06：编辑/删号成功 → 作废控制台首屏缓存
      try { if (_rAe.status === 200) await ccBust(); } catch (e) {}
      return _rAe;
    }
    if (url.pathname === '/api/join_manual' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      const gp2 = groupPassCheck(c, body);
      if (!gp2.ok) return json({ message: gp2.msg }, gp2.status);
      /* 2026-11-10 晚：登记入库也过机器闸门（与「生成链接」同一套 reg_devices 表）。
         背景：APK 装到任何一台新手机上，只要群口令（内嵌在安装包里的 music2026）就能
         一键登记入库 —— 取 CK 是本地行为拦不住，但「往号池里塞号」必须能管住，
         否则软件外流等于号池对所有人开放。
         开关独立：KV 键 APK_REQUIRE_DEV 未设置时，不带 dev 的老版本一律放行（软上线），
         等新版 APK/EXE 铺开、机器都授权完，再把它置 1 才真正开始拒绝。
         放在 groupPassCheck 之后：群口令都不对的请求不会污染 reg_devices 表。 */
      let dchk;
      try {
        dchk = await regDevCheck(body.dev, body.agent || '',
                                 { requireKey: 'APK_REQUIRE_DEV', term: '手机' });
      } catch (e) {
        /* 校验本身炸了（极端情况）：放行 + 留日志。授权是钱的事，但无故停摆更伤。 */
        console.error('join_manual 设备校验异常，临时放行:', e && e.message);
        dchk = { ok: true, dev: '' };
      }
      if (!dchk.ok) return json({ ok: false, message: dchk.msg, dev: dchk.dev || '' }, 403);
      if (dchk.dev) { try { await regDevTouch(dchk.dev, body.agent || ''); } catch (e) {} }
      /* 2026-11-10：满员闸口从「validateCookie 之前」下移到「拿到 uid / 手机号之后」，见下方。
         原位置无法判断这单是不是给已在池的老客户续费/补登，号池一满就再也收不到钱，
         也与 /api/r/submit 的 _alreadyIn 豁免口径不一致（两个入口行为分裂）。 */
      const isG2 = false;
      const myLimit = groupLimitOf(c, isG2);
      const mu = (body.musicU || '').trim();
      if (!mu) return json({ message: '请填写 MUSIC_U' }, 400);
      const email = (body.email || '').trim();
      const ebMail = emailBad(email);
      if (ebMail) return json({ message: ebMail }, 400);
      const v = await validateCookie(mu);
      if (!v.ok) return json({ message: v.msg }, 400);
      // 2026-10-26 修复：网易接口连续不可达时 validateCookie 会用 blake2b「编造」一个 uid 放行
      // （provisional），编造的 uid 与真实 uid 不同 → 网络恢复后同一账号可能被重复登记两条，
      // 而且任何人都能拿任意 80+ 位 hex 串占名额。这条兜底只对管理员通道开放。
      if (v.provisional) {
        const isAdminReg = !!(c.adminPass && String(body.pass || '') === c.adminPass);
        if (!isAdminReg) {
          return json({ message: '网易校验接口暂时不可达（' + (v.diag || '网络异常') + '），为避免登记出错号，请稍后重试。' }, 503);
        }
      }
      const song = await resolveSong(body.link);
      if (!song.ok) return json({ message: song.msg }, 400);
      let expQ = parseExpInput(body.exp);
      if (!expQ.ok) return json({ message: '有效期格式不对：填天数(如730)、日期(2028-10-18)或不填（默认2年）' }, 400);
      const phoneIn = String(body.phone || '').trim();
      const phoneRaw = phoneIn.replace(/[^0-9]/g, '');
      /* 2026-11-10：手机号「填了但格式不对」直接 400，不再静默丢弃。
         原来写错一位数就变成 phone='' → name 记成 qr:<uid>，当场看不出任何异常，
         但这个号从此失去「按手机号认回原单」的凭据 —— 补登/续费链接全都查不到原单。
         不填仍然放行：老版 EXE 主界面没有手机号输入框，在这硬校验会让客服全线登记失败。 */
      if (phoneIn && !/^1\d{10}$/.test(phoneRaw)) {
        return json({ message: '手机号要 11 位、以 1 开头，请检查一下（不填可以；填错这个号以后就认不回原单了）' }, 400);
      }
      const phone = phoneIn ? phoneRaw : '';
      /* 满员闸口（2026-11-10 从上方下移到这里）：已在池的号续费/补登不占新名额，
         口径与 /api/r/submit 的 _alreadyIn 完全一致 —— uid 命中 或 手机号命中 name 即豁免。
         号池到 1200 那天，否则客服给老客户续费会被 429 挡死、收不到钱。 */
      const _m2 = await mergePool();
      const _u2 = String(v.uid || '');
      const _alreadyIn2 = _m2.some(e => e && (String(e.uid) === _u2 || (phone && String(e.name || '') === phone)));
      if (!_alreadyIn2 && activePoolSize(_m2) >= myLimit) {
        return json({ message: '本群名额已满（上限 ' + myLimit + ' 人），暂停登记。已有账号的互听和签到不受影响，请稍后再试或联系群主。' }, 429);
      }
      // 2026-10-27：客服 + 套餐（口径同 /api/join）
      const rc2 = await regCfg();
      const pl2 = planOf(rc2, body.plan);
      /* 2026-11-11：套餐与 exp 打架时以套餐为准（只拦「张冠李戴」的情况）。
         客户端的有效期框是套餐带出的只读框，但旧版 APK（v2.12 及之前）有 bug：
         换套餐后 exp 框不重算（选 1年 还送 730 天），而下面 ent.exp 无条件信客户端
         —— 显示 bug 直接变成入库 bug（客户买 1年 入库 730 天，或 2年 只给 365 天）。
         这里只在「exp 是纯天数 + 恰好等于另一档套餐的天数 + 不等于所选套餐天数」
         时改按所选套餐重算；手填任意天数（如 90）或具体日期、永久，一律照旧放行。 */
      if (expQ.ok && pl2 && /^\d{1,4}$/.test(String(body.exp == null ? '' : body.exp).trim())) {
        const dIn = parseInt(String(body.exp).trim(), 10);
        if (dIn !== pl2.days && (rc2.plans || []).some(p => p.days === dIn)) {
          console.warn('join_manual exp/plan 不符，按套餐重算:', dIn, '->', pl2.label);
          expQ = { ok: true, exp: pl2.exp };
        }
      }
      const ent = { ck: 'MUSIC_U=' + mu, song: song.song, added: beijingDateTime(), name: phone || ('qr:' + v.uid), uid: v.uid, email: email, phone: phone, grp: isG2 ? 2 : 1, exp: expQ.exp || (pl2 ? pl2.exp : undefined),
        agent: normAgent(body.agent), plan: pl2 ? pl2.label : normAgent(body.plan).slice(0, 8) };
      /* 2026-11-10：客服端也可以指定这一单是「续费」还是「补登」（主界面下拉框）。
         不传 / 传 auto → 保持原来的自动判定（号在池里=续费；号不在池但台账原单没到期=补登），
         老版本 EXE 不带这个字段，行为完全不变。
         传了就以它为准，到期日从台账原单取 —— 与自助登记链接同一套口径，理由也一样：
         「号掉线了但客户付了续费」光看数据会被判成免费补登，客户白付钱、客服白干。
         不提供「强制新登记」：新单从今天算一定比在原到期日上累加少，没有业务场景需要它。 */
      const _mk2 = String(body.kind || '').trim();
      if (_mk2 === 'fix' || _mk2 === 'renew') {
        const hist2 = await d1FindLastOrder(String(v.uid || ''), phone);
        if (hist2 === null && !d1ok()) {
          return json({ message: '数据库读不到，暂时没法核对原单，请稍后再试' }, 503);
        }
        if (!hist2) {
          return json({ message: (_mk2 === 'fix' ? '补登' : '续费') + '要先有原单，台账里查不到这个手机号/网易号的记录。'
            + '确实没有原单的，把「这一单是」改回「自动判定」再登记。' }, 404);
        }
        ent.__force = { kind: _mk2, exp: String(hist2.exp || '').slice(0, 10) };
      }
      const r = await addEntry(ent);
      if (!r.ok) return json({ ok: false, message: r.msg }, 400);
      // 2026-10-29 写后自检：控制台/管理后台读的都是 D1，而 addEntry 里的 D1 镜像失败
      // 只 console.error、照样返回 ok:true —— 于是客户端显示「登记成功」、后台网页却
      // 查不到这个号（用户反馈的原话）。这里落库后再回查一次：查不到就补写一次，
      // 还查不到就明确回失败，绝不再假成功。
      let d1Confirmed = null;   // null = 没法确认（D1 查询本身失败，不当成登记失败）
      if (d1ok()) {
        const keyName = phone || ('qr:' + v.uid);
        // 2026-11-08：用 d1FindDup 回查（两条单条件查询走索引），原来是 OR 全池扫 623 行。
        const probe = () => d1FindDup(String(v.uid), keyName);
        let chk = await probe();
        if (chk && !chk.length) {
          console.error('登记后 D1 查不到，补写一次:', String(v.uid));
          await d1Upsert(ent);
          chk = await probe();
        }
        if (chk) d1Confirmed = chk.length > 0;
        if (d1Confirmed === false) {
          return json({ ok: false, message: '这次没能写进数据库（号池刚好抖了一下）。请再点一次「一键登记」，不会重复占名额。' }, 503);
        }
        // 2026-11-05 晚：回查本身失败（chk === null）原来被当成「没法确认」照样回成功 ——
        // D1 配额用尽时就是这个分支，成员看到「登记成功」、控制台却查不到这个号。
        // 现在明确告诉对方失败，不再假成功。
        // 2026-11-08 二次修正：chk === null 是「回查失败」，不是「没写进去」。D1 读额度
        // 打满（code 7500）时必然走到这里，而 addEntry 已经把号写进 KV 权威键
        // （entry:u<uid> / entry:n<name>，KV 才是权威、D1 只是影子库）。所以改查 KV 复核：
        // 有键 = 真写进去了，正常回成功；没键 = 才判失败。
        // 不改的话客服今晚每次手动登记都会「其实成功了却报失败」→ 重试 → 「已登记过」，彻底没法干活。
        if (chk === null) {
          let kvHit = false;
          try {
            const k1 = 'entry:u' + String(v.uid);
            const k2 = 'entry:n' + encodeURIComponent(keyName);
            kvHit = !!(await POOL.get(k1)) || !!(await POOL.get(k2));
          } catch (e) {}
          if (!kvHit) {
            return json({ ok: false, message: '登记没写进数据库（' + d1ErrHint() + '），请稍后重试；这次不会占名额。' }, 503);
          }
          console.log('D1 回查读失败，KV 权威键已确认写入:', String(v.uid));
        }
      }
      // 2026-11-06：登记成功 → 排一封「登记成功 + 加售后群」邮件（Actions 每半小时派发）。
      // 写失败只记日志：邮件少了可以补，登记绝不能因为邮件失败而回错。
      // ref = 登记日：同号同天重复提交被唯一键挡掉；续费（added 变了）会再发一封，属预期。
      try {
        await mailEnqueue(POOL_NAME, String(v.uid), 'reg', String(ent.added || '').slice(0, 10),
          email, ent.name, ent.agent, ent.exp || '');
      } catch (me) { console.error('登记邮件入队失败:', me && me.message); }
      // 2026-11-06：登记成功 → 立即作废控制台首屏缓存（号池马上要在控制台看到这个号）
      try { await ccBust(); } catch (e) {}
      /* 2026-11-10：按类型给不同回执。客服在 EXE 上登记完要能一眼看出「这次是续费，
         有效期延到哪天」/「这次是免费补号，原有效期不变」—— 否则只能去控制台翻。
         文案由服务端下发，老版 EXE 也能直接显示（它本来就显示 message 字段）。 */
      const _rkd = String((r && r.kind) || 'new');
      const _rexp = String((r && r.exp) || '');
      let msg;
      if (_rkd === 'renew') msg = '续费成功：有效期延长到 ' + _rexp + '（在原到期日基础上累加，剩余天数没清零）。';
      else if (_rkd === 'fix') msg = '补号成功：免费补回，原有效期不变（到 ' + _rexp + '）。';
      else msg = '登记成功，次日生效。';
      if (v.provisional) msg += '（注：网易校验接口暂时不可达[' + (v.diag || '') + ']，已跳过在线校验；明天任务会自动复验）';
      return json({ ok: true, uid: String(v.uid), name: phone || ('qr:' + v.uid), pool: POOL_NAME,
        d1: d1Confirmed === true, kind: _rkd, exp: _rexp, message: msg });
    }
    /* ================= 方案C：网页自助扫码登记 ================= */
    /* 买家页面：/r/<8 位码>。不走 PAGE_ROUTES 口令（那是内部成员页，不能发给买家）。 */
    if (url.pathname.indexOf('/r/') === 0 && request.method === 'GET') {
      return new Response(REG_HTML, {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store',
          'X-Frame-Options': 'DENY',
          'Referrer-Policy': 'no-referrer',
        },
      });
    }
    /* 校验 token：给页面显示套餐和剩余时间 */
    if (url.pathname === '/api/r/state') {
      /* 2026-11-10 晚：这条是唯一没有频控的 /api/r/* 接口 —— 每次调用 1 行 D1 读 +
         1 次 KV 读（regTokenGet 的镜像检查），而且无效 code 也照样查库。
         页面上合法买家只调 1 次（刷新几次也就几条），给 300/天/IP 足够；
         计数不可用（D1 挂了/额度尽）时 d1Hit 返回 null，照旧放行。 */
      const stIp = request.headers.get('cf-connecting-ip') || '0';
      const stN = await d1Hit('rst', stIp + ':' + beijingDate());
      if (stN !== null && stN > 300) {
        return json({ ok: false, message: '这条链接打开次数太多了，请稍后再试，或联系客服' }, 429);
      }
      const row = await regTokenGet(url.searchParams.get('t'));
      if (row === undefined) return json({ ok: false, message: '系统正在忙（数据库限流），请 1 分钟后再刷新；多次不行就把这句话发给客服' }, 503);
      if (!row) return json({ ok: false, message: '这个链接无效，请找客服重新要一条' }, 404);
      const stt = regStateOf(row);
      /* 已用掉的链接：回 used 标记，页面显示「登记完成」的绿勾，
         而不是红色报错（买家/他朋友再点开时不该被吓一跳）。不回显登记人信息。 */
      if (stt === 'used') return json({ ok: false, used: true, message: '登记完成，链接已失效。' }, 410);
      if (stt === 'void') return json({ ok: false, message: '这个链接已被作废，请找客服重新要一条' }, 410);
      if (stt === 'expired') return json({ ok: false, message: '这个链接已过期，请找客服重新要一条' }, 410);
      let planLabel = String(row.plan || '');
      try { const pl = planOf(await regCfg(), row.plan); if (pl) planLabel = pl.label; } catch (e) {}
      const leftMs = regTs(row.exp_at) - Date.now();
      return json({
        ok: true, plan: String(row.plan || ''), planLabel: planLabel,
        /* 2026-11-10 晚：Math.round 会把「还剩 12 分钟」显示成「1 小时」，
           买家以为还有一小时结果过期了。改成向上取整，至少不会比实际更短。 */
        left_h: Math.max(1, Math.ceil(leftMs / 3600000)),
        /* 2026-11-10 晚：note 是客服写在链接上的内部备注（比如「已付 3 元」），
           买家页根本不显示，没必要回出去。 */
        /* 2026-11-10：把链接类型告诉买家页 —— 补登要显示「免费、有效期不变」，
           否则买家以为买了新套餐，回头找客服对账。 */
        kind: String(row.kind || 'new'), fix_exp: String(row.fix_exp || ''),
        /* 2026-11-10 晚：原单手机号原来是明文回显 + 自动预填，链接一被转发/截图
           就等于把客户号码送出去了。改成打码，只用于「这是不是我的号」的确认。 */
        fix_name_m: maskPhone(row.fix_name),
      }, 200, { 'Cache-Control': 'no-store' });
    }
    /* 出码：worker 直接向网易申请 unikey，本地生成 PNG
       会话完全无状态 —— sDeviceId 由浏览器生成并回传，cookie 打成 bag 原样带回，
       所以这里一行 KV、一行 D1 都不写（免费额度零消耗）。 */
    if (url.pathname === '/api/r/qrkey') {
      /* 2026-11-09 频控：出码要拿我方出口 IP 去网易申请 unikey，原来完全不限次数（可被刷成风控样本）。
         2026-11-10 晚：60 → 200。60 太紧 —— 手机在用运营商 CGNAT、公司/学校 WiFi
         下，几十个人共享同一个出口 IP，前面几个人换过码就把后面的人全挡成「今天出码
         次数太多」；而单条链接本身已经被 rqc 限死在 8 张码以内，IP 这一层只需要防刷。 */
      const qkIp = request.headers.get('cf-connecting-ip') || '0';
      const qkN = await d1Hit('rqk', qkIp + ':' + beijingDate());
      if (qkN !== null && qkN > 200) return json({ ok: false, message: '今天出码次数太多，请明天再试，或联系客服' }, 429);
      const row = await regTokenGet(url.searchParams.get('t'));
      if (row === undefined) return json({ ok: false, message: '系统正在忙（数据库限流），请 1 分钟后再刷新；多次不行就把这句话发给客服' }, 503);
      if (!row || regStateOf(row) !== 'unused') return json({ ok: false, message: '链接不可用，请刷新页面' }, 410);
      const dev = String(url.searchParams.get('dev') || '').trim();
      if (!/^YD-[0-9a-f]{36}$/.test(dev)) return json({ ok: false, message: '设备号无效，请刷新页面重试' }, 400);
      const bag = { sDeviceId: dev };
      let nk;
      try { nk = await ncNewKey(bag); }
      catch (e) { return json({ ok: false, message: '出码请求失败：' + ((e && e.message) || '网络异常') }, 502); }
      if (nk.err || !nk.key) return json({ ok: false, message: nk.err || '没拿到二维码，点「换一张」重试' }, 502);
      let img = '';
      try { img = await qrPngDataUrl(ncScanUrl(nk.key, dev), { ecc: 'M', scale: 4, quiet: 4 }); }
      catch (e) { console.error('二维码 PNG 生成失败:', e && e.message); }
      if (!img) return json({ ok: false, message: '二维码生成失败，请联系客服' }, 500);
      return json({ ok: true, key: nk.key, dev: dev, bag: ncEncBag(bag), img: img, ttl: 300 },
        200, { 'Cache-Control': 'no-store' });
    }
    /* 轮询一次：801 等待 / 802 已扫待确认 / 803 成功（返回 MUSIC_U） / 800 过期 */
    if (url.pathname === '/api/r/qrcheck') {
      const row = await regTokenGet(url.searchParams.get('t'));
      if (row === undefined) return json({ ok: false, code: 0, message: '系统正在忙，请稍后刷新重试' }, 503);
      if (!row || regStateOf(row) !== 'unused') return json({ ok: false, code: 0, message: '链接不可用' }, 410);
      /* 2026-11-09 频控：页面每 2 秒轮询一次，正常一次扫码 ≤150 次；600 足够「换几张码」。
         没有上限时一个恶意页面可以一直轮询到链接过期，把我方 IP 一直挂在网易的扫码接口上。
         2026-11-10 晚：600 → 1200。一张码 5 分钟 = 150 次轮询，600 只够换 4 张；
         买家连着遇到「这张码网易没放行」时第 5 次就被锁，而文案叫他找客服重发 ——
         其实这条链接还有效、还能用。放到 8 张码，等于把「换几张码」留够。 */
      const qcN = await d1Hit('rqc', regNormCode(url.searchParams.get('t')) + ':' + beijingDate());
      if (qcN !== null && qcN > 1200) {
        return json({ ok: false, code: 0,
          message: '这条链接今天已经试了很多次了，先别刷新，过几小时再来；急的话找客服换一条' }, 429);
      }
      const key = String(url.searchParams.get('key') || '').trim().slice(0, 64);
      if (!key) return json({ ok: false, code: 0, message: '缺少 key' }, 400);
      const dev = String(url.searchParams.get('dev') || '').trim().slice(0, 64);
      const bag = ncDecBag(url.searchParams.get('bag') || '');
      if (dev && !bag.sDeviceId) bag.sDeviceId = dev;
      let p;
      try { p = await ncPollOnce(bag, key); }
      catch (e) { return json({ ok: false, code: 0, message: '稍后自动重试', bag: ncEncBag(bag) }, 200); }
      const out = { ok: true, code: p.code, message: p.message, bag: ncEncBag(bag) };
      if (p.code === 803 && p.musicU) {
        out.mu = p.musicU;
        const pr = await ncProfile(p.musicU);
        if (pr) { out.uid = pr.uid; out.nick = pr.nick; }
      } else if (p.code === 803) {
        /* 手机点了「确认登录」但服务端没收到 MUSIC_U：把诊断信息回给页面显示，
           不然页面只能干等（买家看到的就是「什么都没发生」）。 */
        out.dbg = 'http ' + p.status + ' · cookie[' + (p.cookieNames || []).join('|') + '] · ' + String(p.raw || '').slice(0, 80);
        console.error('qrcheck 803 无 MUSIC_U:', out.dbg);
      }
      return json(out, 200, { 'Cache-Control': 'no-store' });
    }
    /* 提交登记：套餐/客服/天数全部取自 token（前端改不了），成功即原子消耗 token */
    if (url.pathname === '/api/r/submit' && request.method === 'POST') {
      let b0;
      try { b0 = await request.json(); } catch (e) { return json({ ok: false, message: '参数错误' }, 400); }
      const code = regNormCode(b0.t);
      /* 2026-11-09 频控（P0）：这条路径原来没有任何次数限制，一条合法 token 可以无限重试，
         每次 ≈686 行 D1 读 + 3 次网易出站 —— 10 次/秒 ≈ 12 分钟就能烧穿当日 500 万行读，
         同时把我方出口 IP 反复送进网易风控（与 11-08 事故同一条路径）。
         计数不可用（D1 挂了/额度尽）时一律放行：可用性优先，那种时候也烧不了几行。 */
      const ip0 = request.headers.get('cf-connecting-ip') || '0';
      const day0 = beijingDate();
      const hitIp = await d1Hit('rsub', ip0 + ':' + day0);
      if (hitIp !== null && hitIp > 80) {
        return json({ ok: false, message: '今天提交次数太多了，请明天再试，或联系客服' }, 429);
      }
      if (code) {
        const hitTk = await d1Hit('rtok', code + ':' + day0);
        if (hitTk !== null && hitTk > 15) {
          return json({ ok: false, message: '这条链接失败次数太多，请找客服重新要一条' }, 429);
        }
      }
      const row = await regTokenGet(code);
      if (row === undefined) return json({ ok: false, message: '系统正在忙（数据库限流），请 1 分钟后再刷新；多次不行就把这句话发给客服' }, 503);
      if (!row) return json({ ok: false, message: '链接无效，请找客服重新要一条' }, 404);
      if (regStateOf(row) !== 'unused') return json({ ok: false, message: '这个链接已经用过了，不能重复登记' }, 410);

      const mu = String(b0.mu || '').trim();
      if (!mu) return json({ ok: false, message: '没有拿到登录凭证，请重新扫码' }, 400);
      const email = String(b0.email || '').trim();
      const ebMail = emailBad(email);
      if (ebMail) return json({ ok: false, message: ebMail }, 400);
      const phoneRaw = String(b0.phone || '').replace(/[^0-9]/g, '');
      const phone = /^1\d{10}$/.test(phoneRaw) ? phoneRaw : '';
      /* 2026-11-10：手机号改必填。前端已经拦了，这里再拦一次 —— 页面能绕过（老缓存、
         直接打接口），而一个没手机号的号等于丢了身份：补登时认不回来，提醒也发不出去。
         注意只改自助登记这条路，/api/join_manual（客服 EXE 直传）保持原样。 */
      if (!phone) {
        return json({ ok: false,
          message: phoneRaw ? '手机号要 11 位、以 1 开头，请检查一下' : '请填手机号（登录网易云用的那个 11 位手机号）' }, 400);
      }

      const v = await validateCookie(mu);
      if (!v.ok) return json({ ok: false, message: v.msg || '登录凭证已失效，请重新扫码' }, 400);
      if (v.provisional) {
        return json({ ok: false, message: '网易校验接口暂时不可达（' + (v.diag || '网络异常') + '），请稍后重试' }, 503);
      }
      const song = await resolveSong(b0.link);
      if (!song.ok) return json({ ok: false, message: song.msg }, 400);

      /* 名额闸口：与 /api/join_manual 同口径。
         2026-11-10：加「已在池」豁免 —— 续费/补号不会让号池变大（原地更新），
         原来的写法在号池满员时会把老客户续费也一并挡掉，等于满了就再也收不到钱。 */
      const c1 = await cfg();
      const myLimit = groupLimitOf(c1, false);
      const master1 = await mergePool();
      const _u0 = String(v.uid);
      const _alreadyIn = master1.some(e => e && (String(e.uid) === _u0 || (phone && String(e.name || '') === phone)));
      if (!_alreadyIn && activePoolSize(master1) >= myLimit) {
        return json({ ok: false, message: '号池名额已满（上限 ' + myLimit + ' 人），请联系客服，不要重复提交' }, 429);
      }

      /* 2026-11-10 晚 P0（与 /api/regtoken_new 同一根因）：这条链接生成时如果套餐没解析
         出来（plan 现在也找不到 + days=0），有效期就算不出来，addEntry 第一行会把空 exp
         补成「2 年后」—— 等于白送。必须在消耗 token 之前拦下来：拦在后面的话链接已经
         used，买家连重试的机会都没有。补登(fix)继承原单到期日，不受影响。 */
      const rc1 = await regCfg();
      const pl1 = planOf(rc1, row.plan);
      const days1 = Number(row.days) || 0;
      const _tk = String(row.kind || 'new');
      if (_tk !== 'fix' && !(pl1 && pl1.exp) && !(days1 > 0)) {
        return json({ ok: false, message:
          '这条链接上的套餐在服务器上找不到了（可能已改名或下架），这次没有登记。'
          + '请联系客服重新发一条链接 —— 这条链接没有用掉，可以直接丢掉了。' }, 400);
      }

      /* 原子抢 token：两个人同时提交同一条链接，只有一个能进来 */
      const ip = request.headers.get('cf-connecting-ip') || '';
      const ua = request.headers.get('user-agent') || '';
      const name = phone || ('qr:' + v.uid);
      const grabbed = await regTokenUse(code, String(v.uid), name, phone, ip, ua);
      if (grabbed === -1) return json({ ok: false, message: '数据库暂时不可用，请稍后重试' }, 503);
      if (grabbed === 0) return json({ ok: false, message: '这个链接刚刚已被使用，请联系客服' }, 410);

      const agent1 = normAgent(row.agent);
      const ent = {
        ck: 'MUSIC_U=' + mu, song: song.song, added: beijingDateTime(), name: name,
        uid: v.uid, email: email, phone: phone, grp: 1,
        exp: (pl1 && pl1.exp) ? pl1.exp : beijingDatePlus(days1),
        agent: agent1, plan: pl1 ? pl1.label : String(row.plan || '').slice(0, 8),
      };
      /* 2026-11-10：链接上标了补登/续费 → 强制按那个类型走。
         这样客户换手机号、换网易号都不影响判定 —— 类型在发链接时就定了。 */
      if (_tk === 'fix' || _tk === 'renew') {
        ent.__force = { kind: _tk, exp: String(row.fix_exp || '') };
      }
      const r = await addEntry(ent);
      if (!r.ok) {
        /* 2026-11-08：号早就登记过 → 也不算坏事，token 还回去（买家可能扫错了号，
           或者自己本来就在池里）。以前这里保持已用，买家得再找客服要一条链接，
           而他实际上一个号都没登记成功。回滚后同一条链接可继续用，风险≈0：
           同一个号再怎么扫也占不了名额。 */
        if (String(r.msg || '').indexOf('已登记过') >= 0) {
          await regTokenUndo(code);
          return json({ ok: true, uid: String(v.uid),
            message: '这个网易云账号已经在号池里了，无需重复登记。这条链接还没用掉，可以继续用。' });
        }
        await regTokenUndo(code);
        return json({ ok: false, message: r.msg || '登记失败，请再点一次' }, 400);
      }
      /* 写后自检（与 /api/join_manual 同口径，杜绝假成功） */
      let chk = await d1FindDup(String(v.uid), name);
      if (chk && !chk.length) { await d1Upsert(ent); chk = await d1FindDup(String(v.uid), name); }
      if (chk === null) {
        /* 2026-11-08：d1FindDup 返回 null 表示「查询失败」，不是「没写进去」。
           D1 读额度打满（code 7500）时必然走到这里，而上面 addEntry 已经把号写进
           KV 权威键（entry:u<uid> / entry:n<name>）。所以改查 KV 复核：
           有键 = 真的写进去了，正常回成功；没键 = 才判失败。
           顺带修掉一个老 bug：token 在上面已经被 regTokenUse 消耗，原来这里回 503，
           买家看到的是「登记其实成功 / 页面报失败 / 再点又说链接已用过」直接卡死。 */
        let kvHit = false;
        try {
          const k1 = 'entry:u' + String(v.uid);
          const k2 = 'entry:n' + encodeURIComponent(name);
          kvHit = !!(await POOL.get(k1)) || !!(await POOL.get(k2));
        } catch (e) {}
        if (!kvHit) {
          return json({ ok: false, message: '登记没写进数据库（' + d1ErrHint() + '），请稍后重试；这次不会占名额。' }, 503);
        }
        console.log('D1 自检读失败，KV 权威键已确认写入:', String(v.uid));
      } else if (chk.length === 0) {
        /* 2026-11-10 晚：原来只回 503 不回滚 token —— 买家看到「请再点一次」，
           再点却报「链接已经用过了」。上面 addEntry 已确认没写进库，回滚是安全的
           （真写进去了 dup 会命中，addEntry 判「已登记过」并把 token 还回来）。 */
        await regTokenUndo(code);
        return json({ ok: false, message: '这次没能写进数据库，请再点一次「完成登记」（链接已复位，可以重试）' }, 503);
      }

      try {
        await mailEnqueue(POOL_NAME, String(v.uid), 'reg', String(ent.added || '').slice(0, 10),
          email, name, agent1, ent.exp || '');
      } catch (me) { console.error('登记邮件入队失败:', me && me.message); }
      try { await ccBust(); } catch (e) {}

      /* 2026-11-10：按类型给不同文案。续费必须让客户看见「有效期延到哪天」，
         补号要说明「免费、不额外收费」—— 否则客服每天都要回答同一句话。 */
      let _msg;
      if (r.kind === 'renew') {
        _msg = '续费成功：有效期已延长到 ' + String(r.exp || '') +
               '（在原到期日基础上累加，原来剩下的天数不会清零）。';
      } else if (r.kind === 'fix') {
        _msg = '补号成功：这个号之前掉线了，本次免费补回、不额外收费，原有效期不变（到 ' +
               String(r.exp || '') + '）。';
      } else {
        _msg = '登记成功，明天开始生效。';
      }
      return json({ ok: true, uid: String(v.uid), name: name,
        kind: String(r.kind || 'new'), exp: String(r.exp || ''), message: _msg });
    }
    /* ---- 客服生成 / 查看 / 作废登记链接（口令：KV REG_TOKEN_PASS） ---- */
    if (url.pathname === '/api/regtoken_new' && request.method === 'POST') {
      let b1;
      try { b1 = await request.json(); } catch (e) { return json({ ok: false, message: '参数错误' }, 400); }
      const pw = await regPass();
      /* 2026-11-10：控制台也能生成链接（管理员自己补发、发补登链接）。
         先按客服口令判，不对再按控制台满权限口令判 —— 客服请求不带 user 字段，
         consoleRole 会立刻回 null，不产生额外 KV 读，客服这条路完全没变慢。 */
      let passOk = !!pw && String(b1.pass || '') === pw;
      if (!passOk) passOk = await consoleAuthFull(b1);
      if (!passOk) {
        if (!pw) return json({ ok: false, message: '尚未配置生成口令（KV 键 REG_TOKEN_PASS），该功能未开放' }, 503);
        return json({ ok: false, message: '生成口令不正确' }, 403);
      }
      const agent = normAgent(b1.agent);
      const rc2 = await regCfg();
      const pl2 = planOf(rc2, b1.plan);
      const pObj = (rc2.plans || []).find(it => it.key === String(b1.plan || '') || it.label === String(b1.plan || ''));
      /* ===== 2026-11-10 晚 P0：套餐必须解析成功，否则这条链接会白送 2 年 =====
         原来的写法：planOf 返回 null 时【照样生成】，只是 days 传 0。买家提交时
         /api/r/submit 也算不出有效期（exp=undefined），最后落到 addEntry 第一行
         `if (!entry.exp) entry.exp = beijingDatePlus(730)` —— 2 年后到期；
         renew 更糟：planDaysOf(2年后) ≈ 730，直接在客户原到期日上 +730 天。
         全程没有任何报错，客服看到「已生成」、买家看到「登记成功」，只有对账时才发现。
         触发场景两个，都是日常操作：
           a) 控制台下架 days=0 的套餐（现在是「永久」80 元）→ 存量永久链接全变 2 年；
           b) 控制台改套餐名 → 客服电脑上还开着的 EXE 用本地缓存的旧名字生成
              （refresh_reg_cfg 只在启动时跑一次）→ 新链接 days=0 → 2 年。
         补登(fix)不读套餐（有效期继承原单），所以只拦 new/renew。
         放在吃配额之前：套餐不对不该白占一条/天的额度。 */
      const tokKind = (String(b1.kind || '') === 'fix') ? 'fix'
        : (String(b1.kind || '') === 'renew' ? 'renew' : 'new');
      if (tokKind !== 'fix' && !pl2) {
        return json({ ok: false, bad_plan: true, message:
          '套餐「' + String(b1.plan || '(空)') + '」不在服务器当前的套餐表里（可能已改名或下架）。'
          + '请在软件里重新选一次套餐；下拉里如果还是旧名字，重启软件刷新套餐列表。'
          + '这条链接没有生成，也不占今天的条数。' }, 400);
      }
      /* 2026-11-09：链接有效期只留两档（24 小时 / 3 天）。原来接受 1~720 任意值，
         EXE 里还多一档 7 天 —— 链接在群里转手后存活太久，等于把入口长期挂着。 */
      const hours = (Number(b1.hours) === 72) ? 72 : 24;
      /* 2026-11-09：每台机器/每客服 每日生成配额（默认 200；单机配额可在控制台「设备授权」里单独设）。
         EXE 里的生成口令是硬编码的，EXE 一旦外流就等于谁都能造链接；配额把最坏情况
         压成「每天 200 条」，且异常量在 rate_limit 里一眼看得出来。计数不可用则放行。
         2026-11-10：60 → 200（生成≠成交，重发重试都占次数）；同时接入机器授权校验。 */
      const dchk = await regDevCheck(b1.dev, agent);
      if (!dchk.ok) {
        return json({ ok: false, need_auth: true, dev: dchk.dev || '', message: dchk.msg }, 403);
      }
      await regDevTouch(dchk.dev, agent);
      /* 2026-11-10 晚：原来只有 dchk.quota 为 0（老版 EXE 不带机器码）时才读 KV
         REG_TOKEN_DAILY_MAX，而授权设备的 quota 恒 >0（默认 200）⇒ 这个 KV 配置
         永远不生效，想临时把全局限到 50 条根本改不动。改成取两者较小值：
         KV 能往下压（应急），不能往上抬（单机配额仍以控制台「设备授权」为准）。 */
      let cap = dchk.quota || 200;
      try {
        const kvCap = parseInt(cleanKV(await POOL.get('REG_TOKEN_DAILY_MAX')), 10);
        if (kvCap > 0) cap = Math.min(cap, kvCap);
      } catch (e) {}
      const genKey = dchk.dev ? ('d' + dchk.dev) : String(agent || '-');
      const genN = await d1Hit('rtn', genKey + ':' + beijingDate());
      if (genN !== null && genN > cap) {
        return json({ ok: false, message: '今天生成链接已达上限（' + cap + ' 条/天），需要更多请联系管理员' }, 429);
      }
      /* ===== 2026-11-10：链接类型（新登记 / 续费 / 补登）=====
         为什么必须在生成链接时定：补登（免费、继承原单到期日）和续费（收钱、到期日累加）
         在「客户提交」那一刻长得完全一样 —— 都是「号不在池里 + 原单还没到期」。
         只靠提交时的字段猜，猜错一次就是白送一个套餐（判成补登）或客户付了钱没延长
         （判成补登）。这件事只有客服在发链接时知道，所以固化在 token 上。
         补登必须指定原单（fix_ref = 原单手机号或网易 uid），服务端从台账里取到期日。
         tokKind 在上面「套餐必须解析成功」那段就算好了（要赶在吃配额之前拦下来）。 */
      let tokFixExp = '', tokFixRef = '', tokFixName = '';
      if (tokKind !== 'new') {
        const ref = String(b1.fix_ref || b1.ref || '').replace(/[^0-9A-Za-z_-]/g, '').slice(0, 40);
        if (!ref) {
          return json({ ok: false,
            message: (tokKind === 'fix' ? '补登' : '续费') + '链接必须先选原单（填客户的手机号或网易 UID）' }, 400);
        }
        /* 2026-11-10 修 bug：原来用 `/^\d{6,}$/` 判断「这是 uid」，而手机号是纯数字、
           长度也 ≥6，于是客服填手机号时实际查的是 uid=手机号，必然查不到 → 一律报
           「没查到原单」，补登/续费链接根本发不出去。改成手机号优先按 name 查，
           查不到再按 uid 兜一次（11 位纯数字的 uid 也照样能查）。 */
        const refIsPhone = /^1\d{10}$/.test(ref);
        /* 2026-11-10 晚：控制台「选原单」会把那一笔的到期日一起传上来（fix_exp）。
           原来服务端完全不看它，一律取最近一笔 —— 客服选的是 9 月那单，实际按 11 月
           那单的到期日算续费基数，静默错单。传了就按 exp 精确定位；老 EXE 不传这个
           字段，refExp 为空，行为与原来完全一致。 */
        const refExp = String(b1.fix_exp || '').slice(0, 10);
        let hist = null;
        if (refIsPhone) hist = await d1FindLastOrder(null, ref, refExp);
        if (!hist) hist = await d1FindLastOrder(ref, '', refExp);
        if (!hist) {
          /* d1FindLastOrder 读失败也回 null，这里没法区分「真没有原单」和「这次没读出来」，
             所以文案两种可能都写上 —— 绝不能让人以为「客户没买过」。 */
          return json({ ok: false,
            message: '按「' + ref + '」没查到原单（也可能是数据库刚好忙）。换个手机号或网易 UID 再试；'
                   + '确实没有原单的客户请按「新登记」发链接' }, 404);
        }
        tokFixExp = String(hist.exp || '').slice(0, 10);
        tokFixRef = ref;
        /* 原单手机号：台账 name 是 11 位数字才认（老号可能存的是 qr:/manual: 占位名）。
           买家页拿它预填，客户手机号没换就不用再手打一遍。 */
        const hn = String(hist.name || '').replace(/[^0-9]/g, '');
        tokFixName = /^1\d{10}$/.test(hn) ? hn : '';
        if (!tokFixExp) {
          return json({ ok: false, message: '原单没记录到期日（历史数据缺失），不能做补登/续费，请按新登记处理' }, 400);
        }
        /* 补登只在原套餐有效期内免费 —— 原单已经到期再「补登」等于白送一整个套餐。 */
        if (tokKind === 'fix' && tokFixExp !== 'forever' && isExpiredExp(tokFixExp)) {
          return json({ ok: false,
            message: '这个原单已经到期（' + tokFixExp + '），不能走补登（补登只在原套餐有效期内免费）。'
                   + '客户要继续用得发「续费」或「新登记」链接' }, 400);
        }
      }
      /* 2026-11-10：补登不存套餐 —— 补登继承原单到期日，套餐对它没有任何作用。
         前端也不再要求选套餐（选了也白选），这里直接写空，免得列表里出现
         误导性的「套餐：1月」，让人以为补登还买了时长。 */
      const one = await regTokenNew(agent,
        tokKind === 'fix' ? '' : (pl2 ? pl2.key : String(b1.plan || '').slice(0, 16)),
        tokKind === 'fix' ? 0 : (pObj ? (Number(pObj.days) || 0) : 0),
        b1.note, hours, tokKind, tokFixExp, tokFixRef, tokFixName);
      if (!one) return json({ ok: false, message: '生成失败（' + d1ErrHint() + '）' }, 503);
      const origin = url.origin;
      return json({
        ok: true, code: one.code, code_only: one.code,
        link: origin + '/r/' + one.code,
        short: origin.replace(/^https?:\/\//, '') + '/r/' + one.code,
        exp_at: one.exp_at, hours: hours, agent: agent, plan: pl2 ? pl2.label : '',
        kind: tokKind, fix_exp: tokFixExp, fix_ref: tokFixRef, fix_name: tokFixName,
      });
    }
    /* ---- 客服查原单（生成补登/续费链接前先确认这一单） ----
       2026-11-10：EXE 里有生成口令、没有控制台口令，所以不能复用 /api/console/findorder。
       这里只按「完整手机号 / 完整网易 UID」精确查（两条单条件查询，都走索引），
       不用 LIKE —— ledger 全表扫描在额度打满时最容易被拖死。 */
    if (url.pathname === '/api/regtoken_find' && request.method === 'POST') {
      let bf;
      try { bf = await request.json(); } catch (e) { return json({ ok: false, message: '参数错误' }, 400); }
      const pwf = await regPass();
      let okf = !!pwf && String(bf.pass || '') === pwf;
      if (!okf) okf = await consoleAuthFull(bf);
      if (!okf) return json({ ok: false, message: pwf ? '生成口令不正确' : '生成口令未配置' }, 403);
      const qf = String(bf.q || '').replace(/[^0-9A-Za-z_-]/g, '').slice(0, 40);
      if (qf.length < 5) return json({ ok: false, message: '请输完整手机号 或 完整网易 UID' }, 400);
      const COLS = 'uid,name,plan,exp,day,start,rb';
      let rows = await d1All('SELECT ' + COLS + ' FROM ledger WHERE pool=? AND uid=? ORDER BY day DESC, id DESC LIMIT 5',
                             [POOL_NAME, qf]);
      if (rows !== null && !rows.length) {
        rows = await d1All('SELECT ' + COLS + ' FROM ledger WHERE pool=? AND name=? ORDER BY day DESC, id DESC LIMIT 5',
                           [POOL_NAME, qf]);
      }
      if (rows === null) return json({ ok: false, message: '数据库读不到，请稍后再试（不是没有原单）' }, 503);
      const uids = [...new Set(rows.map(r => String(r.uid || '')).filter(Boolean))];
      const alive = {};
      if (uids.length) {
        const a = await d1All('SELECT uid FROM accounts WHERE pool=? AND uid IN (' + uids.map(() => '?').join(',') + ')',
                              [POOL_NAME].concat(uids));
        if (a) for (const x of a) alive[String(x.uid)] = 1;    // 读失败就当「不在池」，只影响显示
      }
      return json({ ok: true, rows: rows.map(r => ({
        uid: String(r.uid || ''), name: String(r.name || ''), plan: String(r.plan || ''),
        exp: String(r.exp || ''), day: String(r.day || ''), start: String(r.start || ''),
        rb: Number(r.rb) || 0, alive: !!alive[String(r.uid)],
      })) });
    }
    if (url.pathname === '/api/regtoken_list' && request.method === 'POST') {
      let b2;
      try { b2 = await request.json(); } catch (e) { return json({ ok: false, message: '参数错误' }, 400); }
      const pw2 = await regPass();
      let passOk2 = !!pw2 && String(b2.pass || '') === pw2;
      if (!passOk2) passOk2 = await consoleAuthFull(b2);       // 2026-11-10：控制台也能查
      if (!passOk2) {
        if (!pw2) return json({ ok: false, message: '尚未配置生成口令（KV 键 REG_TOKEN_PASS），该功能未开放' }, 503);
        return json({ ok: false, message: '生成口令不正确' }, 403);
      }
      const w = [], ps = [];
      if (b2.agent) { w.push('agent=?'); ps.push(normAgent(b2.agent)); }
      const stq = String(b2.state || '');
      /* 2026-11-10：「已过期」是算出来的状态（state 仍是 unused，只是 exp_at 过了），
         库里根本没有 state='expired' 这种值 —— 原来走到 else 分支拼 state=?
         永远查回 0 行，所以筛选框里像「没有过期链接」一样。这里单独按时间区间判。 */
      const nowIso = regIso(Date.now());
      if (stq === 'unused') { w.push("state='unused' AND exp_at > ?"); ps.push(nowIso); }
      else if (stq === 'expired') { w.push("state='unused' AND exp_at <= ?"); ps.push(nowIso); }
      else if (stq) { w.push('state=?'); ps.push(stq); }
      /* 2026-11-11：客服查询（手机版 APK 用）—— q 支持三种：
         ① 整条链接（自动截 /r/ 后面的编码）② 编码本身 ③ 客户手机号。
         编码走主键 token=?；手机号走 phone=?（reg_tokens 没有 phone 索引，但表就几千行、
         客服手动查询频率很低，全扫可接受，且是单条件不踩 OR 毁索引的坑）。
         判定顺序：先试 /r/ 编码和裸编码；纯数字（6~15 位）当手机号；都不像 → 明确报错不猜。

         2026-11-11 晚改：客服反馈「必须输完整链接或完整 8 位编码太难用」⇒ 改模糊匹配，
         只要 3 位以上片段就行（编码 /r/ 后的、手机号的任意几位都认）。
         - 编码：token LIKE '%片段%'（库内 token 已是 regNormCode 规范化的大写，输入也先规范化）
         - 手机号：phone LIKE '%片段%'，同时并一条 token LIKE（纯数字片段也算编码片段）
         LIKE 走不了索引，但 reg_tokens 只有几千行、客服手点一次，代价和原来的 phone=? 全扫一个量级；
         代价是太短的片段会一次捞回几十条无关记录，反而更难找，所以 <3 位直接拒绝并说清楚。 */
      const q2 = String(b2.q || '').trim();
      if (q2) {
        const m2 = q2.match(/\/r\/([A-Za-z0-9]+)/i);
        const raw2 = m2 ? m2[1] : q2;
        const alnum2 = raw2.replace(/[^A-Za-z0-9]/g, '');
        const dig2 = q2.replace(/[^0-9]/g, '');
        const onlyDigits = /^[0-9\s\-]+$/.test(q2);
        if (!alnum2) {
          return json({ ok: false, message: '认不出要查的内容：粘登记链接、填编码的一段、或填客户手机号的几位' }, 400);
        }
        if (alnum2.length < 3) {
          return json({ ok: false, message: '太短了：编码或手机号至少填 3 位，太短会查出一堆无关链接' }, 400);
        }
        if (onlyDigits) {
          const like2 = '%' + dig2 + '%';
          w.push('(phone LIKE ? OR token LIKE ?)'); ps.push(like2, like2);
        } else {
          w.push('token LIKE ?'); ps.push('%' + regNormCode(alnum2) + '%');
        }
      }
      const lim = Math.max(1, Math.min(300, Number(b2.limit) || 80));
      const rows = await d1All(
        'SELECT token,agent,plan,days,note,state,ctime,exp_at,used_at,uid,uname,phone,kind,fix_exp,fix_ref,fix_name FROM reg_tokens' +
        (w.length ? (' WHERE ' + w.join(' AND ')) : '') + ' ORDER BY ctime DESC LIMIT ' + lim, ps);
      if (rows === null) return json({ ok: false, message: '数据库读不到（' + d1ErrHint() + '）' }, 503);
      return json({ ok: true, n: rows.length, rows: rows.map(r => Object.assign({}, r, { state: regStateOf(r) })) });
    }
    if (url.pathname === '/api/regtoken_void' && request.method === 'POST') {
      let b3;
      try { b3 = await request.json(); } catch (e) { return json({ ok: false, message: '参数错误' }, 400); }
      const pw3 = await regPass();
      let passOk3 = !!pw3 && String(b3.pass || '') === pw3;
      if (!passOk3) passOk3 = await consoleAuthFull(b3);       // 2026-11-10：控制台也能作废
      if (!passOk3) {
        if (!pw3) return json({ ok: false, message: '尚未配置生成口令（KV 键 REG_TOKEN_PASS），该功能未开放' }, 503);
        return json({ ok: false, message: '生成口令不正确' }, 403);
      }
      const n = await d1Changes("UPDATE reg_tokens SET state='void' WHERE token=? AND state='unused'",
                               [regNormCode(b3.code)]);
      if (n === -1) return json({ ok: false, message: '数据库不可用' }, 503);
      if (!n) return json({ ok: false, message: '没找到可作废的链接（可能已用掉或已作废）' }, 404);
      /* 作废必须立刻反映到 KV 镜像，否则 D1 读挂时买家还能用这条已作废的链接。 */
      try {
        const k = 'regtok:' + regNormCode(b3.code);
        const kv = await POOL.get(k);
        if (kv) { const o = JSON.parse(kv); o.state = 'void'; await POOL.put(k, JSON.stringify(o), { expirationTtl: 259200 }); }
      } catch (e) {}
      return json({ ok: true, message: '已作废' });
    }
    // ---- 补录/修改通知邮箱（老号自助通道，只改 email 一个字段，其余原样）----
    if (url.pathname === '/api/updatemail' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      const gp3 = groupPassCheck(c, body);
      if (!gp3.ok) return json({ message: gp3.msg }, gp3.status);
      // 2026-10-26 补频控：本接口只要手机号对得上就能改邮箱，没有任何验证。
      // 这是给「老号补录/换邮箱」用的自助通道，不能加验证码（会打断正常补录），
      // 但必须挡住脚本批量撞号：按出口 IP 每天 20 次。D1 不可用时回退 KV，绝不让频控静默失效。
      const ip = String(request.headers.get('CF-Connecting-IP') || 'unknown').slice(0, 64);
      let hits = await d1Hit('um', ip + ':' + beijingDate());
      if (hits === null) {
        try {
          const rk = 'um:' + ip + ':' + beijingDate();
          const cnt = parseInt(await POOL.get(rk), 10) || 0;
          hits = cnt + 1;
          if (cnt < 20) await POOL.put(rk, String(hits), { expirationTtl: 172800 });
        } catch (e) { hits = 0; }
      }
      if (hits > 20) return json({ message: '今天修改邮箱的次数过多，请明天再试或联系群主。' }, 429);
      const email = (body.email || '').trim();
      const ebMail = emailBad(email);
      if (ebMail) return json({ message: ebMail }, 400);
      const phone = (body.phone || '').replace(/[０-９]/g, c => String.fromCharCode(c.charCodeAt(0) - 65248)).replace(/[^0-9]/g, '');
      const mu = (body.mu || '').trim();
      if (!phone && !mu) return json({ message: '请填写手机号或 MUSIC_U（至少填一个）' }, 400);
      const master = await mergePool();
      let target = null;
      if (mu) {
        const v = await validateCookie(mu);
        if (!v.ok) return json({ message: v.msg }, 400);
        target = master.find(e => e.uid != null && String(e.uid) === String(v.uid)) || null;
      } else {
        target = master.find(e => e.name === phone) || null;
      }
      if (!target) return json({ message: '没有找到你的登记记录：请检查手机号/MUSIC_U 是否填错；如果还没登记过，请用上方的登记方式。' }, 404);
      // 2026-10-26：留一条审计痕迹（谁/何时/把哪个号从什么邮箱改成了什么）。
      // Worker 日志（wrangler tail / CF 面板）可查，出纠纷时能定位。
      console.log('updatemail', JSON.stringify({ ip, key: entryKeyOf(target), uid: String(target.uid != null ? target.uid : ''), from: String(target.email || ''), to: email, at: new Date().toISOString() }));
      target.email = email;
      // 与 addEntry 同一套写入机制：独立键权威写 + master 缓存刷新 + 同步号池 Secrets
      await POOL.put(entryKeyOf(target), JSON.stringify(target));
      // 2026-10-22 修复：这里原先只写 KV，但所有读路径（控制台/管理后台/下次编辑）都已切到 D1，
      // 结果成员自助改的邮箱第二天就被 D1 里的旧值覆盖回去，等于没改。必须同步镜像到 D1。
      if (!(await d1Upsert(target))) {
        console.error('改邮箱的 D1 镜像失败（KV 已写入，可用 /api/resync 补齐）');
      }
      const updated = master.map(e => entryKeyOf(e) === entryKeyOf(target) ? target : e);
      // master 缓存不再回写（2026-10-22）：读者全走 D1，entry: 独立键才是权威
      await pushPool(updated);
      try { await refreshPoolSnap(); } catch (e) {}
      try { await ccBust(); } catch (e) {}
      return json({ message: '已保存：' + email + '。之后账号有变化，会发邮件到这个邮箱。' });
    }
    // ---- 二维码登录通道（实测网易是否放行 CF 机房 IP）----
    // GET /api/qr_key  → 网易申请 unikey
    // GET /api/qr_check?key=xxx → 轮询：800过期/801等待/802已扫/803成功（成功时从 set-cookie 提取 MUSIC_U 放进 JSON 返回）
    if (url.pathname === '/api/qr_key' && request.method === 'GET') {
      const r = await fetch(BASE + '/api/login/qrcode/unikey', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': UA, 'Referer': BASE + '/' },
        body: 'type=1',
      });
      const text = await r.text();
      return new Response(text, { status: r.status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    if (url.pathname === '/api/qr_check' && request.method === 'GET') {
      const key = (url.searchParams.get('key') || '').trim();
      if (!key) return json({ message: '缺少 key' }, 400);
      const r = await fetch(BASE + '/api/login/qrcode/client/login?key=' + encodeURIComponent(key) + '&type=1', {
        headers: { 'User-Agent': UA, 'Referer': BASE + '/' },
      });
      const text = await r.text();
      let out = text;
      try {
        const j = JSON.parse(text);
        if (j.code === 803) {
          const sc = r.headers.get('set-cookie') || '';
          const m = sc.match(/MUSIC_U=([^;]+)/);
          j.musicU = m ? m[1] : '';
          out = JSON.stringify(j);
        }
      } catch (e) { /* 非 JSON（被风控页拦截）原样返回，前端据此判失败 */ }
      return new Response(out, { status: r.status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    // 隐藏管理接口：仍用 GROUP_PASS 保护（2026-10-20 登记接口已去掉群口令，此口令降级为群主管理专用暗号），从 KV 主表重新把 NB_POOL_1..5 推回 GitHub Secrets（KV 丢失/Secrets 异常时一键恢复）
    if (url.pathname === '/api/resync' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      // 2026-10-22：补 `!c.groupPass` —— 以前 KV 里没配 GROUP_PASS 时，body.pass="" 即可通过
      // 2026-10-26：改用 adminPassOk —— 配了 ADMIN_PASS 就只认管理口令，不再接受群口令
      if (!adminPassOk(c, body.pass)) return json({ message: '管理口令错误' }, 403);
      let master = await mergePool();
      const pushRes = await pushPool(master, true);   // 强制推：resync 就是「现在就要一份全量快照到 Secrets」
      return json({ message: `已从 KV 重新同步 ${master.length} 条到 GitHub Secrets（NB_POOL_1..${(pushRes && pushRes.slots) || 0}，片数按号池体积自动伸缩）。` });
    }
    // 失效账号清理：Actions 跑完发现 cookie 失效的号，按 name/uid 从号池剔除并重写分片
    // 直邮回执（2026-11-03 新增，纯新增路由）：run.py / signin.py 真把「账号信息过期」
    // 邮件发出去之后调这里，把 dead_notice 里对应条目直接标成 sent，
    // 免得 notify_dead.py 隔 12 小时再给同一个号主发第二封一样的邮件。
    // 只动 state='pending' 的行，重复调用无副作用；认证口径与 /api/report_dead 一致。
    if (url.pathname === '/api/dead_mailed' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      if (!adminPassOk(c, body.pass)) return json({ message: '管理口令错误' }, 403);
      if (!d1ok()) return json({ ok: false, message: 'D1 未绑定' }, 503);
      const poolN = String(body.pool || POOL_NAME);
      const stamp = bjStamp();
      let n = 0;
      for (const nm of (body.names || []).slice(0, 200)) {
        const s = String(nm || '').trim();
        if (!s) continue;
        try {
          const ok = await d1Run("UPDATE dead_notice SET state='sent',sent_at=?,skip_reason=? WHERE pool=? AND state='pending' AND name=?",
            [stamp, '直邮已发', poolN, s]);
          if (ok) n++;   // d1Run 内部吞异常只回 false，按返回值计数才看得出 SQL 是否真跑通
        } catch (_e) {}
      }
      return json({ ok: true, marked: n, pool: poolN });
    }
    if (url.pathname === '/api/report_dead' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      // 2026-10-26：改用 adminPassOk —— 这是「能删号」的接口，绝不能再认半公开的群口令
      if (!adminPassOk(c, body.pass)) return json({ message: '管理口令错误' }, 403);
      const deadSet = new Set((body.dead || []).map(x => String(x)));
      if (!deadSet.size) return json({ message: '没有需要清理的账号。' });
      const master = await mergePool();
      const before = master.length;
      const deadEntries = master.filter(e => deadSet.has(String(e.name)) || deadSet.has(String(e.uid)));
      if (!deadEntries.length) return json({ message: `没有匹配到账号（号池 ${before} 个）。` });

      // ---- 死号判定（2026-10-23 改版：客户端重试 + 立即删除）----
      // 旧逻辑（2026-10-22）：第一次判死只打 suspect_at，隔 18~36 小时下一轮再判死才真删。
      // 问题：号主要白等一整天，期间「已判死但还挂在池子里」的号既不能听也不能被听，
      // 客服也没法提前帮他重新登记。
      // 新逻辑：客户端（run.py）在判死前已经重试过 3 次（要求至少 2 次明确失效），
      // 确认之后带 confirm=true 上报 → 服务端直接删号；客户端随即给号主发「账号信息过期」邮件。
      // 也就是说「确认」这一步从服务端的时间窗口挪到了客户端的重试，效果等价但不用等一天。
      // 不带 confirm 的旧客户端仍走原来的 suspect_at 双重确认，向后兼容。
      const forceConfirm = body.confirm === true;
      // 2026-11-04：forceConfirm 也照常查一遍（多一次全池 SELECT，578 行 <1ms）。
      // 原有「18~36 小时二次确认」口径不变，susMap 给不带 confirm 的老客户端用。
      // 2026-11-09：不再需要 relMap（「保留 + 等号主重登」这条支路已取消，改为验 CK 后立即删）。
      let susRows = null;
      try { susRows = await d1All('SELECT uid,suspect_at FROM accounts WHERE pool=?', [POOL_NAME]); } catch (_e) { susRows = null; }
      const susMap = {};
      if (susRows) for (const r of susRows) {
        susMap[String(r.uid)] = String(r.suspect_at || '');
      }
      const nowMs = Date.now();
      const suspects = [], confirmed = [];
      for (const e of deadEntries) {
        if (forceConfirm) { confirmed.push(e); continue; }   // 客户端已重试确认 → 直接删
        if (!susRows) { suspects.push(e); continue; }        // D1 读不到 → 无法确认，保守只打标不删
        const prev = susMap[String(e.uid)] || '';
        const t = prev ? Date.parse(prev) : NaN;
        const ageH = isNaN(t) ? -1 : (nowMs - t) / 3600000;
        if (ageH >= 18 && ageH <= 36) confirmed.push(e); else suspects.push(e);
      }
      const stamp = new Date(nowMs).toISOString();
      if (susRows) {
        for (const e of suspects) {
          await d1Run('UPDATE accounts SET suspect_at=? WHERE pool=? AND uid=?', [stamp, POOL_NAME, String(e.uid)]);
        }
      }
      // 2026-10-29 修复「删失败也给号主发过期邮件」：
      // 旧顺序是「先删 KV 键 → 再 d1Delete」，而 d1Delete 失败只 return false、不抛异常，
      // 外层 try/catch 什么也拦不到，deleted 依旧原样返回全部名单。结果：D1 那行还在
      //（下一次 mergePool 会从 D1 把它读回来、继续播放），号主却已收到「账号信息过期」。
      // 现在顺序反过来：先删 D1，只有真删成功的才删 KV 键 / 进墓碑 / 计进 deleted / 发信。
      // ---- 2026-11-09 口径：客户端反复确认失效 → 立刻删，服务端不再插「账号还在就保留」的复核 ----
      // 删掉旧 B 方案的原因：它用别的活号查 user/detail/<uid>，只能证明「账号还在网易」，
      // 证明不了「这个 CK 还能用」。而最常见的失效恰恰是「CK 死了、账号还在」（换设备/被顶号），
      // 于是号被保留 + 发「请重登」，号主不理就无限挂着（11-09 手工清 6 个，最短挂 5 天）。
      // 客户端的确认已经够硬（run.py.login_by_cookie）：先 weapi account/get 拿 profile，
      // 拿不到再用 v1 每日推荐二次验证，必须「code=200 但 0 首」才算明确失效，且 3 次里 2 次明确失败。
      // 服务端原来想再加一道「验 CK」，2026-11-09 实测证明不可行：明文 account/get 与
      // v1 每日推荐对池内随机 6 个健康号全部回「未登录/0 首」（当天 dead_log 只删了 8 个），
      // 该判据在没有播放环境的出口 IP 上没有区分度 —— 再加只会制造误判，所以整段删掉。
      // 唯一保留的防线：单次最多删 MAX_DEL 个，防止客户端一次 bug 把全池报成死号。
      const reloginNotify = [];   // 不再产生「保留+重登提醒」；字段留着只为兼容 run.py 的解析
      let keptUnknown = 0;
      const keptNames = [];
      const MAX_DEL = 40;
      if (confirmed.length > MAX_DEL) {
        const over = confirmed.splice(MAX_DEL);
        keptUnknown = over.length;
        for (const e of over) keptNames.push(e.name || String(e.uid));
        console.warn('单次上报 ' + (MAX_DEL + keptUnknown) + ' 个死号，超过上限，本轮只删前 ' + MAX_DEL + ' 个，其余下轮再判');
      }
      const keepNote = keptNames.length
        ? '；另有 ' + keptNames.length + ' 个超过单次删除上限 ' + MAX_DEL + '，本轮未处理、下轮再判：' + keptNames.join('、')
        : '';
      const hasD1 = d1ok();
      const delRes = await Promise.all(confirmed.map(async e => {
        if (!hasD1) return { e: e, ok: true };      // D1 未绑定：纯 KV 模式，按成功处理
        let ok = false;
        try { ok = (await d1Delete(e)) === true; } catch (_e) { ok = false; }
        return { e: e, ok: ok };
      }));
      const reallyGone = delRes.filter(x => x.ok).map(x => x.e);
      const delFail = delRes.filter(x => !x.ok).map(x => x.e);
      if (delFail.length) {
        console.error('D1 删除失败（这些号保留在池内、不发信）: ' + delFail.map(e => e.name || e.uid).join('、'));
      }
      // 删除走独立键（单键删除，无竞态），并记墓碑防缓存复活；再刷新 master 缓存
      await Promise.all(reallyGone.map(async e => { try { await POOL.delete(entryKeyOf(e)); } catch (_e) {} }));
      const deadEkeys = reallyGone.map(e => entryKeyOf(e));
      if (deadEkeys.length) {
        try {
          const log = new Set(await getDeadLog());
          for (const k of deadEkeys) log.add(k);
          // 只留最近 500 条，防止无限增长
          await POOL.put('dead_log', JSON.stringify([...log].slice(-500)));
        } catch (e) {}
      }
      // 2026-11-03 补缺口：自动删号（cookie_invalid）以前完全不进 dead_notice 队列 ——
      //   号主通知全靠 run.py 回执后直邮，直邮没配好/失败就一封都发不出去（11-03 全池扫 94 个
      //   job 日志，找不到任何「已直邮号主」）。现在删成功的号一律入队 pending：
      //   run.py / signin.py 直邮成功会回调 /api/dead_mailed 把这条标成 sent；
      //   没标成的由主群 notify_dead.py 隔 12 小时兜底发（两群共用同一张 D1 表，pool 各自独立）。
      //   12 小时窗口顺带挡掉「删完当天就重登」的误报（判据在 /api/dead_pending 的 skip_returned）。
      let queued = 0;
      for (const e of reallyGone) {
        try { if (await d1QueueNotice(e)) queued++; } catch (_e) {}
      }
      await d1LogDead(reallyGone, 'cookie_invalid');
      const gone = new Set(deadEkeys);
      const after = master.filter(e => !gone.has(entryKeyOf(e)));
      // master 缓存不再回写（2026-10-22）：读者全走 D1，entry: 独立键才是权威
      await pushPool(after);
      try { await refreshPoolSnap(); } catch (e) {}
      const nm = arr => arr.map(e => e.name || e.uid).join('、');
      // deleted：真正被删掉的号名。run.py 靠它决定「给谁发过期邮件」——
      // 只有删成功了才发，避免「邮件说已删除、号其实还在池里」。
      const deleted = reallyGone.map(e => e.name || String(e.uid));
      const failNote = delFail.length
        ? `；${delFail.length} 个 D1 删除失败（${delFail.map(e => e.name || e.uid).join('、')}）仍留在池内，未发信，下轮会重试`
        : '';
      return json({ ok: true, deleted: deleted, relogin: reloginNotify,
        message: `本次确认清理 ${confirmed.length} 个${confirmed.length ? '（' + nm(confirmed) + '）' : ''}`
        + `，实际删除 ${reallyGone.length} 个${failNote}${keepNote}；`
        + `新增疑似 ${suspects.length} 个（需下一轮再次判死才删除${suspects.length ? '：' + nm(suspects) : ''}），`
        + `剩余 ${after.length} 个。` });
    }
    // ---- 2026-11-04：号主重登提醒的「已发信」回执（纯新增路由）----
    // report_dead 把「CK 失效但账号还在」的号通过 relogin 字段回给 run.py，
    // run.py 直邮成功后调本接口写 relogin_at。作用有二：
    //   ① 之后不再重复发信，直到号主重新登记（d1Upsert 里 CK 变化会把它清空）；
    //   ② buildPlanFrom 据此把这个号摘出听众环 —— 它已经听不了，不该再占应跑名额。
    if (url.pathname === '/api/relogin_mailed' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      if (!adminPassOk(c, body.pass)) return json({ message: '管理口令错误' }, 403);
      if (!d1ok()) return json({ ok: false, message: 'D1 未绑定' }, 503);
      const names = (Array.isArray(body.names) ? body.names : []).map(x => String(x)).filter(Boolean).slice(0, 100);
      if (!names.length) return json({ ok: true, wrote: 0 });
      const stamp = new Date().toISOString();
      let wrote = 0;
      for (const nm of names) {
        try {
          await d1Run('UPDATE accounts SET relogin_at=? WHERE pool=? AND (name=? OR uid=?)',
                      [stamp, POOL_NAME, nm, nm]);
          wrote++;
        } catch (_e) {}
      }
      return json({ ok: true, wrote: wrote });
    }
    // ---- 2026-11-09：CK 失效超时清理的手动/对端触发入口 ----
    // 正常由 CF 每日 cron 自动跑（scheduled 主路径），这里只给两种场景用：
    //   ① 对端 dz 没有 scheduled handler，由 hz 主 cron 用对穿口令调它；
    //   ② 人工排障：POST {pass: 管理口令 或 对穿口令} 立刻扫一遍。
    // 认证同时接受 peerKey（跨群）与 adminPass（管理），都不配则拒绝。
    if (url.pathname === '/api/relogin_sweep' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      const byPeer = await peerPassOk(body.pass);
      if (!byPeer && !adminPassOk(c, body.pass)) return json({ message: '口令错误' }, 403);
      const r = await pruneStaleRelogin(body.days);
      return json(r, r.ok === false ? 503 : 200);
    }
    // ====================================================================
    // 手动删号的「通知号主」判定队列（2026-10-26 新增，纯新增路由）
    // 为什么要单独一套：控制台删号是在 worker 里直接删 D1 行完成的，没有 Python 进程
    //   参与，而 smtp.qq.com:465 只能从 GitHub Actions 发 → 手动删号的号主一封邮件都收不到。
    // 为什么不能无脑发：实测最近 12 条 manual 里 7 条是 hz→dz 迁移、2 条是删了当天重登，
    //   只有 3 条真离开系统。给前 9 位发「账号信息过期，麻烦重新登记」纯属误报（他们号好好的）。
    // 判定口径（用户 2026-10-26 定）：删除时入队(pending) → 等满 12 小时 → 再判
    //   ① 同 uid 或同账号名在任一池又出现了 → 迁移/重登 → 不发（skip_returned）
    //   ② 没留邮箱 → 不发（skip_noemail）
    //   ③ 其余视为真删 → 返回给 Actions，由 notify.py 发那封现成模板
    // 并发保护：判完立刻标 claimed；发信成功后回调 /api/dead_sent 标 sent，失败回调 retry
    //   退回 pending；claimed 超过 2 小时自动回 pending（runner 中途挂掉不至于永久卡住）。
    // ====================================================================
    if (url.pathname === '/api/dead_pending' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      if (!c.assignPass) return json({ ok: false, message: '未配置 ASSIGN_PASS' }, 503);
      if (body.pass !== c.assignPass && !(c.adminPass && body.pass === c.adminPass)) return json({ message: '口令错误' }, 403);
      if (!d1ok()) return json({ ok: false, message: 'D1 未绑定' }, 503);
      const waitH = Math.max(0, Number(body.wait_h != null ? body.wait_h : 12) || 0);
      const nowMs = Date.now();
      const cutoff = bjStamp(nowMs - waitH * 3600000);
      // claimed 卡住超过 2 小时的回退，避免 runner 挂死把这批永久占住
      await d1Run("UPDATE dead_notice SET state='pending',claimed_at=NULL WHERE state='claimed' AND claimed_at<=?",
        [bjStamp(nowMs - 2 * 3600000)]);
      const pend = await d1All(
        'SELECT pool,uid,name,email,removed_at,kind FROM dead_notice WHERE state=? AND removed_at<=? ORDER BY removed_at LIMIT 100',
        ['pending', cutoff]) || [];
      const toSend = [], skipped = [];
      for (const r of pend) {
        const uid = String(r.uid || ''), nm = String(r.name || '');
        // 「回来了吗」：同 uid 或同账号名出现在任一池（hz/dz 都算）→ 迁移或重登，不该发
        let back = '';
        let alivePub = -1;
        const conds = [], vals = [];
        if (uid) { conds.push('uid=?'); vals.push(uid); }
        if (nm) { conds.push('name=?'); vals.push(nm); }
        if (conds.length) {
          const q = await d1All('SELECT pool,pub FROM accounts WHERE ' + conds.join(' OR ') + ' LIMIT 1', vals);
          if (q && q.length) { back = String(q[0].pool || ''); alivePub = Number(q[0].pub) || 0; }
        }
        // 2026-11-05：到期降级为公益号的通知，号本来就在池里 —— 不能再用「还在池里」判回池。
        // 该发的条件：号还在 且 pub 仍是 1（说明号主没续费）；
        // 已经续费（重新登记同一个号 → pub 回到 0）就不发，视为已回池。
        const isExpiredNotice = (String(r.kind || '') === 'expired');
        if (back && !(isExpiredNotice && alivePub === 1)) {
          skipped.push({ pool: r.pool, uid: uid, name: nm, removed_at: r.removed_at, state: 'skip_returned', why: '已在 ' + back + ' 池' }); continue;
        }
        const em = String(r.email || '').trim();
        if (!em) { skipped.push({ pool: r.pool, uid: uid, name: nm, removed_at: r.removed_at, state: 'skip_noemail', why: '未登记邮箱' }); continue; }
        toSend.push({ pool: r.pool, uid: uid, name: nm, email: em, removed_at: String(r.removed_at) });
      }
      const stamp = bjStamp();
      const isDry = body.dry === true;   // 干跑：只返回名单，不改任何状态（核对用）
      if (!isDry) {
        for (const s of skipped) {
          await d1Run('UPDATE dead_notice SET state=?,skip_reason=?,claimed_at=? WHERE pool=? AND uid=? AND removed_at=?',
            [s.state, s.why, stamp, s.pool, s.uid, s.removed_at]);
        }
        for (const s of toSend) {
          await d1Run("UPDATE dead_notice SET state='claimed',claimed_at=? WHERE pool=? AND uid=? AND removed_at=?",
            [stamp, s.pool, s.uid, s.removed_at]);
        }
      }
      return json({ ok: true, dry: isDry, wait_h: waitH, cutoff: cutoff, to_send: toSend, skipped: skipped });
    }
    // 发信结果回写：sent = 已发；retry = 本轮失败，退回 pending 下次再试
    if (url.pathname === '/api/dead_sent' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      if (!c.assignPass) return json({ ok: false, message: '未配置 ASSIGN_PASS' }, 503);
      if (body.pass !== c.assignPass && !(c.adminPass && body.pass === c.adminPass)) return json({ message: '口令错误' }, 403);
      if (!d1ok()) return json({ ok: false, message: 'D1 未绑定' }, 503);
      const items = (body.items || []).slice(0, 200);
      const retry = body.result === 'retry';
      const stamp = bjStamp();
      let n = 0;
      for (const it of items) {
        const ok = retry
          ? await d1Run("UPDATE dead_notice SET state='pending',claimed_at=NULL,sent_at=NULL WHERE pool=? AND uid=? AND removed_at=?",
            [String(it.pool || ''), String(it.uid || ''), String(it.removed_at || '')])
          : await d1Run("UPDATE dead_notice SET state='sent',sent_at=? WHERE pool=? AND uid=? AND removed_at=?",
            [stamp, String(it.pool || ''), String(it.uid || ''), String(it.removed_at || '')]);
        if (ok) n++;
      }
      return json({ ok: true, updated: n, result: retry ? 'retry' : 'sent' });
    }
    // ====================================================================
    // 号主邮件队列三接口（2026-11-06 新增）：登记成功通知 + 到期提醒。
    // 与 dead_notice 同一套路：worker 只排队/判定，SMTP 发送在 GitHub Actions（notify_mail.py）。
    // /api/mail_scan   到期提醒扫描：每天北京时间只扫一次（KV 闸门 MAIL_SCAN_DAY），
    //                  对全池（两群共用一个 D1）pub=0 且有 exp 有邮箱的号算剩余天数，
    //                  命中 MAIL_STAGES 档位就入队；ref 对不上当前 exp 的 pending 一律作废（续费了）。
    //                  rows_read ≈ accounts 全表一遍（~1200 行/天），额度无压力。
    // /api/mail_pending  领取待发：state=pending → claimed（2 小时超时自动回退），
    //                  发送前再验一遍账号现况（在池/有邮箱/公益号/exp 没变），群号此时按最新 reg_cfg 现查。
    // /api/mail_sent   回写：sent / retry（失败退回 pending 重试，累计 3 次失败标 dropped 放弃）。
    // ⚠ 读失败一律 503 绝不当空表（11-06 铁律）。
    // ====================================================================
    if (url.pathname === '/api/mail_scan' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      if (!c.assignPass) return json({ ok: false, message: '未配置 ASSIGN_PASS' }, 503);
      if (body.pass !== c.assignPass && !(c.adminPass && body.pass === c.adminPass)) return json({ message: '口令错误' }, 403);
      if (!d1ok()) return json({ ok: false, message: 'D1 未绑定' }, 503);
      const dry = body.dry === true, force = body.force === true;
      const today = beijingDate();
      if (!force) {
        let lastDay = null;
        try { lastDay = await POOL.get('MAIL_SCAN_DAY'); } catch (e) {}
        if (lastDay === today) {
          return json({ ok: true, skipped: true, day: today, dry: dry, message: '今天已扫过（KV 闸门），要重扫带 force=true' });
        }
      }
      // 主扫描：pub=0 且有 exp（非 forever）且有邮箱 —— 公益号/永久号/无邮箱一律不提醒。
      // 2026-11-06：加 pool=主群过滤 —— 定制群（dz）不参与任何邮件通知（用户指定），
      //   不加过滤会把 dz 的号也扫进到期提醒。
      const rows = await d1All("SELECT pool,uid,name,email,agent,exp FROM accounts " +
        "WHERE pool=? AND pub=0 AND exp IS NOT NULL AND exp<>'' AND exp<>'forever' AND email<>''", [POOL_NAME]);
      if (rows === null) return json({ ok: false, message: '读 accounts 失败（' + (_d1LastErr || 'D1 异常') + '），本次不扫描不落闸门' }, 503);
      const curExp = new Map();          // pool|uid → 当前 exp（含没命中档位的号，用于作废旧 pending）
      const will = [];
      for (const r of rows) {
        const exp = String(r.exp || '').slice(0, 10);
        if (!/^\d{4}-\d{2}-\d{2}$/.test(exp)) continue;
        curExp.set(String(r.pool || '') + '|' + String(r.uid != null ? r.uid : ''), exp);
        const left = Math.round((Date.parse(exp + 'T00:00:00Z') - Date.parse(today + 'T00:00:00Z')) / 86400000);
        if (!(left >= 0)) continue;      // 已过期（等 prune 降级成公益号），不再提醒
        const stage = MAIL_STAGES.find(s => left <= s);
        if (!stage) continue;
        will.push({ pool: String(r.pool || ''), uid: String(r.uid != null ? r.uid : ''), kind: 'exp' + stage,
          ref: exp, email: String(r.email || '').trim(), name: String(r.name || ''), agent: String(r.agent || ''), exp: exp, left: left });
      }
      // 作废对不上号的旧 pending：续费（exp 变了）/ 降级（pub=1，上面查不到）都算
      const pend = await d1All("SELECT pool,uid,kind,ref FROM mail_queue WHERE kind LIKE 'exp%' AND state='pending'", []);
      if (pend === null) return json({ ok: false, message: '读 mail_queue 失败（' + (_d1LastErr || 'D1 异常') + '），本次不扫描不落闸门' }, 503);
      let dropped = 0;
      if (dry) {
        return json({ ok: true, dry: true, day: today, scanned: rows.length, will_enqueue: will.length,
          will: will.slice(0, 50) });
      }
      for (const p of pend) {
        if (curExp.get(String(p.pool || '') + '|' + String(p.uid || '')) === String(p.ref || '')) continue;
        const okD = await d1Run("UPDATE mail_queue SET state='dropped',skip_reason=? WHERE pool=? AND uid=? AND kind=? AND ref=? AND state='pending'",
          ['exp 已变更（续费/降级），旧提醒作废', String(p.pool || ''), String(p.uid || ''), String(p.kind || ''), String(p.ref || '')]);
        if (okD) dropped++;
      }
      for (const w of will) {
        try { await mailEnqueue(w.pool, w.uid, w.kind, w.ref, w.email, w.name, w.agent, w.exp); } catch (e) {}
      }
      try { await POOL.put('MAIL_SCAN_DAY', today); } catch (e) {}
      return json({ ok: true, dry: false, day: today, scanned: rows.length, will_enqueue: will.length, dropped_stale: dropped });
    }
    if (url.pathname === '/api/mail_pending' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      if (!c.assignPass) return json({ ok: false, message: '未配置 ASSIGN_PASS' }, 503);
      if (body.pass !== c.assignPass && !(c.adminPass && body.pass === c.adminPass)) return json({ message: '口令错误' }, 403);
      if (!d1ok()) return json({ ok: false, message: 'D1 未绑定' }, 503);
      const dry = body.dry === true;
      const limit = Math.min(50, Math.max(1, parseInt(body.limit, 10) || 50));   // ≤50：校验查询参数 ≤100（铁律）
      const stamp = bjStamp();
      await d1Run("UPDATE mail_queue SET state='pending',claimed_at=NULL WHERE state='claimed' AND claimed_at<=?",
        [bjStamp(Date.now() - 2 * 3600000)]);
      const pend = await d1All('SELECT pool,uid,kind,ref,email,name,agent,exp,created_at FROM mail_queue ' +
        // 2026-11-06：登记邮件优先 —— 补发积压时新用户登记也只需等下一班（30 分钟内），
        //   到期提醒是天级节奏，排后面没影响。
        "WHERE state='pending' ORDER BY CASE WHEN kind='reg' THEN 0 ELSE 1 END, created_at LIMIT " + limit, []);
      if (pend === null) return json({ ok: false, message: '读 mail_queue 失败（' + (_d1LastErr || 'D1 异常') + '）' }, 503);
      if (!pend.length) return json({ ok: true, dry: dry, to_send: [], skipped: [] });
      // 批量校验账号现况（一次 IN 查询，参数 ≤ 2+50）
      const uids = [];
      for (const p of pend) { const u = String(p.uid != null ? p.uid : ''); if (u && !uids.includes(u)) uids.push(u); }
      const pools = [];
      for (const p of pend) { const pl = String(p.pool || ''); if (pl && !pools.includes(pl)) pools.push(pl); }
      const ph = uids.map(() => '?').join(',');
      const plh = pools.map(() => '?').join(',');
      const accs = await d1All('SELECT pool,uid,pub,exp,email,agent,name FROM accounts WHERE pool IN (' + plh + ') AND uid IN (' + ph + ')',
        pools.concat(uids));
      if (accs === null) return json({ ok: false, message: '读 accounts 校验失败（' + (_d1LastErr || 'D1 异常') + '），本轮不发放' }, 503);
      const accMap = new Map();
      for (const a of accs) accMap.set(String(a.pool || '') + '|' + String(a.uid != null ? a.uid : ''), a);
      const rc = await regCfg();
      const toSend = [], skipped = [];
      for (const p of pend) {
        const key = String(p.pool || '') + '|' + String(p.uid != null ? p.uid : '');
        const a = accMap.get(key);
        let why = '';
        if (!a) why = '账号已不在池里（被删/迁移）';
        else if (!String(a.email || '').trim()) why = '未登记邮箱';
        else if (String(p.kind || '').indexOf('exp') === 0) {
          if (Number(a.pub) === 1) why = '已降级公益号（永久有效，不提醒）';
          else if (String(a.exp || '').slice(0, 10) !== String(p.ref || '')) why = 'exp 已变更（续费了），本轮作废';
        }
        if (why) {
          skipped.push({ pool: p.pool, uid: p.uid, kind: p.kind, ref: p.ref, why: why });
          if (!dry) await d1Run("UPDATE mail_queue SET state='skipped',skip_reason=? WHERE pool=? AND uid=? AND kind=? AND ref=? AND state='pending'",
            [why, String(p.pool || ''), String(p.uid || ''), String(p.kind || ''), String(p.ref || '')]);
          continue;
        }
        // 群号发送时现查：客服改群号立即生效，不用重发
        const agent = normAgent(a.agent || p.agent);
        const grp = agentGroupOf(rc, agent);
        const item = { pool: String(p.pool || ''), uid: String(p.uid != null ? p.uid : ''), kind: String(p.kind || ''),
          ref: String(p.ref || ''), email: String(a.email || '').trim(), name: String(a.name || ''), agent: agent,
          group: grp, exp: String(a.exp || '').slice(0, 10), created_at: String(p.created_at || '') };
        toSend.push(item);
        if (!dry) await d1Run("UPDATE mail_queue SET state='claimed',claimed_at=? WHERE pool=? AND uid=? AND kind=? AND ref=? AND state='pending'",
          [stamp, item.pool, item.uid, item.kind, item.ref]);
      }
      return json({ ok: true, dry: dry, to_send: toSend, skipped: skipped });
    }
    // /api/mail_cron_test  排障用：手动执行一次 dispatchMailQueue（CF cron 发令腿的同一函数），
    // 用来区分「发令函数本身坏了」还是「CF cron 没触发」。口令同 mail_pending。跑完看 KV cron:mail:last。
    if (url.pathname === '/api/mail_cron_test' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      if (!c.assignPass) return json({ ok: false, message: '未配置 ASSIGN_PASS' }, 503);
      if (body.pass !== c.assignPass && !(c.adminPass && body.pass === c.adminPass)) return json({ message: '口令错误' }, 403);
      const r = await dispatchMailQueue();
      return json({ ok: true, result: r });
    }
    if (url.pathname === '/api/mail_sent' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      if (!c.assignPass) return json({ ok: false, message: '未配置 ASSIGN_PASS' }, 503);
      if (body.pass !== c.assignPass && !(c.adminPass && body.pass === c.adminPass)) return json({ message: '口令错误' }, 403);
      if (!d1ok()) return json({ ok: false, message: 'D1 未绑定' }, 503);
      const items = (body.items || []).slice(0, 100);
      const retry = body.result === 'retry';
      const stamp = bjStamp();
      let n = 0, dropped = 0;
      // 2026-11-06 重试上限：用户要求「尝试几次不行就放弃，别浪费额度」。
      // attempts 每次发信失败 +1，满 3 次标 dropped（skip_reason 注明）。
      // claimed 2 小时超时回退不算次数（那是崩溃恢复，不是真发过）。
      for (const it of items) {
        if (retry) {
          const rs = await d1All("SELECT attempts FROM mail_queue WHERE pool=? AND uid=? AND kind=? AND ref=? AND state='claimed'",
            [String(it.pool || ''), String(it.uid || ''), String(it.kind || ''), String(it.ref || '')]);
          if (rs === null) continue;   // 读失败不动状态（铁律 3c：读失败≠读到空，下轮 claimed 超时自然回退）
          const att = Number((rs[0] && rs[0].attempts) || 0);
          if (att + 1 >= 3) {
            const ok = await d1Run("UPDATE mail_queue SET state='dropped',attempts=attempts+1,claimed_at=NULL,sent_at=NULL,skip_reason='连续3次发送失败，放弃' WHERE pool=? AND uid=? AND kind=? AND ref=? AND state='claimed'",
              [String(it.pool || ''), String(it.uid || ''), String(it.kind || ''), String(it.ref || '')]);
            if (ok) { n++; dropped++; }
          } else {
            const ok = await d1Run("UPDATE mail_queue SET state='pending',attempts=attempts+1,claimed_at=NULL,sent_at=NULL WHERE pool=? AND uid=? AND kind=? AND ref=? AND state='claimed'",
              [String(it.pool || ''), String(it.uid || ''), String(it.kind || ''), String(it.ref || '')]);
            if (ok) n++;
          }
        } else {
          const ok = await d1Run("UPDATE mail_queue SET state='sent',sent_at=? WHERE pool=? AND uid=? AND kind=? AND ref=? AND state='claimed'",
            [stamp, String(it.pool || ''), String(it.uid || ''), String(it.kind || ''), String(it.ref || '')]);
          if (ok) n++;
        }
      }
      return json({ ok: true, updated: n, dropped: dropped, result: retry ? 'retry' : 'sent' });
    }
    // ====================================================================
    // 进阶控制台（2026-10-22 新增，全部为纯新增路由，不改动任何既有路由）
    // 页面 /console；数据流：两群 run.py 播完顺带查工作台 → POST /api/snap 归口本 worker KV
    //（key: snap:<日期>:<pool>:<分片>，90 天过期）→ 控制台按日期聚合展示 + 日环比 + 编辑。
    // 登录：账号/密码均 xx1031（可在 KV 加 CONSOLE_PASS 键覆盖默认密码；用户名固定 xx1031）。
    // ====================================================================
    if (url.pathname === '/console' && request.method === 'GET') {
      // 2026-10-25：打开页面顺手在后台补一批歌曲/账号元数据（不阻塞响应、失败静默）
      try { if (globalThis.CTX && typeof globalThis.CTX.waitUntil === 'function') globalThis.CTX.waitUntil(backfillMeta()); } catch (e) {}
      return new Response(CONSOLE_HTML, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    if (url.pathname === '/api/console/login' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      // 2026-10-27：登录返回 role（full=满权限 / ro=只读）。页面据此把「编辑、删号、客服名单」
    // 这些写入口全部关掉；真正的拦截在服务端写接口上，前端只是不让人白点。
      const role = await consoleRole(body);
      return json(role ? { ok: true, role: role } : { ok: false, message: '账号或密码错误' }, role ? 200 : 403, CORS);
    }
    // 快照写入（run.py 每个分片跑完后上报一次；两群归口本 KV）
    if (url.pathname === '/api/snap' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      const c = await cfg();
      const pass = String(body.pass || '');
      const pool = body.pool === 'dz' ? 'dz' : 'hz';
      // 鉴权：主群走本群群口令；定制群走跨群对穿口令（本 worker 的 PEER_PASS 键里存的就是定制群口令）
      if (pool === 'dz') {
        const peerPass = cleanKV(await POOL.get('PEER_PASS'));
        if (!peerPass || pass !== peerPass) return json({ message: '口令错误' }, 403, CORS);
      } else {
        // 2026-10-29：主群鉴权同时接受 ASSIGN_PASS。
        // 以前只认 KV 里的 GROUP_PASS，而群口令机制早已取消（groupPassCheck 恒 true）——
        // 哪天有人顺手把 KV 的 GROUP_PASS 删掉，凌晨整轮快照全部 403，而且只打印不告警。
        // ASSIGN_PASS 是 GitHub Secret + KV 双份，是这里唯一稳定的口令来源。
        if (!pass || (pass !== c.groupPass && pass !== c.assignPass)) {
          return json({ message: '口令错误' }, 403, CORS);
        }
      }
      const date = /^\d{4}-\d{2}-\d{2}$/.test(body.date || '') ? body.date : beijingDate();
      const slice = String(body.slice == null ? 'x' : body.slice).replace(/[^\w-]/g, '').slice(0, 8) || 'x';
      const accs = (body.accs && typeof body.accs === 'object') ? body.accs : {};
      const clean = {};
      // 2026-10-26 新增：data 层 furtherVipGetTime 旁路留档（run.py workbench_info 的 periodEnd）。
      // ⚠️ 实测该字段【不是当前任务周期的结束日】（10-26 全池验证：按它判「已过期」的号 95% 仍在涨），
      // 所以只存不判，控制台的「周期归零」仍用「昨日≥80%」的启发式。别拿它当到期日。
      // 为什么不塞进 clean：clean 会原样写进 D1 snapshots 表，多一个字段就撞「列不存在」。
      // 只在上午补采（slice=am）这一路收集，避免凌晨 250 个分片并发读改写同一个 KV 键。
      const perIn = {};
      const collectPeriod = (slice === 'am');
      for (const k of Object.keys(accs).slice(0, 300)) {
        const a = accs[k] || {};
        clean[String(k).slice(0, 16)] = {
          rate: a.rate == null ? null : Number(a.rate) || 0,
          rpc30: a.rpc30 == null ? null : Number(a.rpc30) || 0,
          cnt: a.cnt == null ? null : Number(a.cnt) || 0,
          // 2026-10-23 修复：run.py 上报的字段名是 missions，这里原来只读 mis →
          // 「任务」列永远空。两个名字都认，优先 mis。
          mis: (a.mis && typeof a.mis === 'object') ? a.mis
               : ((a.missions && typeof a.missions === 'object') ? a.missions : {}),
          dur: a.dur == null ? null : Number(a.dur) || 0,
        };
        if (collectPeriod) {
          const peRaw = String(a.periodEnd || '');
          if (/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(peRaw)) perIn[pool + '|' + String(k).slice(0, 16)] = peRaw;
        }
      }
      // 时长沉淀：uid→登记歌曲时长(秒)。跟号走不跟日期走，存 console:durs（永不过期，随改随覆盖）。
      // body.durs 供一次性回填用；纯回填（accs 空）时不写当日快照，防止空分片覆盖。
      const incoming = {};
      for (const k of Object.keys(clean)) { if (clean[k].dur) incoming[k] = clean[k].dur; }
      if (body.durs && typeof body.durs === 'object') {
        for (const k of Object.keys(body.durs).slice(0, 500)) {
          const v = Number(body.durs[k]);
          if (v > 0) incoming[String(k).slice(0, 16)] = Math.round(v);
        }
      }
      let dursChanged = 0;
      if (Object.keys(incoming).length) {
        // 2026-10-22：console:durs 是单键，250 片并发 get→put 必然互相覆盖 → 主存储改 D1 durs 表
        //（按 (pool,uid) UPSERT，无竞态）。
        // 2026-10-22 第三批：D1 写成功就不再写 KV。以前不论成败都双写，而 KV「同一个 key 每秒
        // 只能写 1 次」，250 片又是并发上报 → 这份"备份"大部分请求直接 429 失败，白烧当日
        // 1000 次写额度，却根本保不住数据。现在只在 D1 写失败时才落 KV。
        if (d1ok()) dursChanged = await d1DursWrite(pool, incoming);
        if (!dursChanged) {
          try {
            let cur = {};
            try { cur = JSON.parse(await POOL.get('console:durs') || '{}'); } catch (e) {}
            for (const k of Object.keys(incoming)) { if (cur[k] !== incoming[k]) { cur[k] = incoming[k]; dursChanged++; } }
            if (dursChanged) await POOL.put('console:durs', JSON.stringify(cur));
          } catch (e) { /* 时长沉淀失败不影响快照 */ }
        }
      }
      // 周期结束日沉淀（2026-10-26）：跟号走不跟日期走，存 console:period 单键，
      // 键带池前缀（'hz|uid' / 'dz|uid'），防同一个号挂两池时互相覆盖。
      // 只在 slice=am 的补采里写，凌晨 250 片并发上报不碰这个键（KV 单键读改写会互相覆盖）。
      if (Object.keys(perIn).length) {
        try {
          let cur = {};
          try { cur = JSON.parse(await POOL.get('console:period') || '{}'); } catch (e) {}
          const merged = Object.assign({}, cur, perIn);
          const ks = Object.keys(merged);
          if (ks.length > 3000) for (const k of ks.slice(0, ks.length - 3000)) delete merged[k];
          await POOL.put('console:period', JSON.stringify(merged));
        } catch (e) { /* 周期日沉淀失败不影响快照 */ }
      }
      // 实跑名单（2026-10-22）：run.py 把本片真正跑完播放的 uid 一起报上来，
      // 供 /api/coverage 核对「应跑 vs 实跑」。放在空快照提前返回之前，避免只有名单没有指标时丢数据。
      const ranUids = Array.isArray(body.ran) ? body.ran.map(x => String(x)).filter(Boolean).slice(0, 400) : [];
      const ranWrote = ranUids.length ? await d1RunsWrite(date, pool, ranUids, slice) : 0;
      if (!Object.keys(clean).length) {
        return json({ ok: true, dursMerged: dursChanged, ran: ranWrote, note: '纯时长回填，未写快照' }, 200, CORS);
      }
      const key = 'snap:' + date + ':' + pool + ':' + slice;
      // 2026-10-22：主存储改 D1 snapshots 表。
      // 2026-10-22 第三批：D1 写成功就不再写 KV。以前每片每天都写一个 snap: 键，200 片就是
      // 200 次 KV 写/天（免费额度 1000 的 20%），而控制台读早已切到 D1 —— 这份纯粹白烧额度。
      // 现在只有 D1 写失败时才落 KV：真正需要它的时候它才存在。
      const d1okSnap = await d1SnapWrite(date, pool, clean);
      if (!d1okSnap) {
        try {
          await POOL.put(key, JSON.stringify({ ts: new Date().toISOString(), accs: clean }), { expirationTtl: 7776000 });
        } catch (e) {
          return json({ message: '快照写入失败：D1 与 KV 均不可用（' + ((e && e.message) || e) + '）' }, 500, CORS);
        }
      }
      return json({ ok: true, key: key, count: Object.keys(clean).length, ran: ranWrote, d1: d1okSnap,
                    kv_fallback: !d1okSnap }, 200, CORS);
    }
    // ---- 覆盖率核对（2026-10-22 新增）：应跑 vs 实跑 ----
    // 以前没有任何地方核对「这一轮到底跑了多少个号」：250 片里有几片静默失败，job 依旧是绿的。
    // 按天返回「计划听众数 / 实跑号数 / 缺口名单」，由 coverage.yml 每天调一次并发邮件。
    if (url.pathname === '/api/coverage' && request.method === 'GET') {
      const c = await cfg();
      const pass = url.searchParams.get('pass') || '';
      if (!c.assignPass) return json({ ok: false, message: '未配置 ASSIGN_PASS' }, 503);
      if (pass !== c.assignPass && !(c.adminPass && pass === c.adminPass)) return json({ ok: false, message: '口令错误' }, 403);
      if (!d1ok()) return json({ ok: false, message: 'D1 未绑定' }, 503);
      const day = /^\d{4}-\d{2}-\d{2}$/.test(url.searchParams.get('day') || '')
        ? url.searchParams.get('day') : beijingDate();
      const poolQ = url.searchParams.get('pool') || POOL_NAME;
      // 2026-11-09：expected 优先取「当轮 plan 快照」（首轮 plan 时落地，见 planSnapPut）。
      // 没有快照（本改动之前的日子 / D1 读不到）才回退实时 buildPlan —— 回退口径与改之前完全一致。
      let expected = null, expSrc = '', snapAt = '';
      const snap = await planSnapGet(day, poolQ);
      if (snap) {
        expected = snap.uids; expSrc = 'snap'; snapAt = snap.at;
      } else {
        const plan = await buildPlan(day);
        if (!plan.ok) return json({ ok: false, message: plan.msg }, 503);
        expected = plan.plans.filter(x => x.pool === poolQ).map(x => String(x.uid));
        expSrc = 'live';
      }
      const rows = await d1All('SELECT uid FROM runs WHERE day=? AND pool=?', [day, poolQ]);
      // 2026-11-06：读失败不能当成「一个都没跑」——那会发出「覆盖率 0%」的假告警，
      // 且缺口名单是全部号，等于把故障指向错误的方向。直接报错。
      if (!rows) return json({ ok: false, message: 'D1 查询失败（runs 表读不到）' }, 503);
      const ranSet = new Set(rows.map(r => String(r.uid)));
      const expSet = new Set(expected);
      const missing = expected.filter(u => !ranSet.has(u));
      const extra = [...ranSet].filter(u => !expSet.has(u));
      return json({ ok: true, day: day, pool: poolQ, expected: expected.length, ran: ranSet.size,
                    missing_n: missing.length, missing: missing.slice(0, 80), extra_n: extra.length,
                    extra: extra.slice(0, 80), expected_src: expSrc, snap_at: snapAt,
                    pct: expected.length ? Math.round(ranSet.size * 1000 / expected.length) / 10 : 0 });
    }
    // ---- 断点续跑（2026-11-02 新增）----
    // 起因：11-02 主群 brush(55) 被 GitHub 托管 runner 杀在半路（hosted runner lost communication），
    // 这一片 5 个号里有的已播完、有的还没开始。整片重跑会让已播完的号当天播第二遍（每号 28~32 次）。
    // 原来 runs 表只在「整片跑完」时随 /api/snap 一次性上报，片被中断就一条记录都没有，
    // 无从判断哪些号已经播过。改法：
    //   POST /api/run_mark —— run.py 每个号播完立刻增量落一条 runs 记录；
    //   GET  /api/run_done —— 任何一片开跑前拉当天已跑名单，跳过已在名单里的号。
    // 幂等：正常跑（当天第一次）名单为空，行为与以前完全一致；重跑时才可能命中。
    if (url.pathname === '/api/run_done' && request.method === 'GET') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      const c = await cfg();
      const pass = url.searchParams.get('pass') || '';
      if (!c.assignPass) return json({ ok: false, message: '未配置 ASSIGN_PASS' }, 503, CORS);
      if (pass !== c.assignPass && !(c.adminPass && pass === c.adminPass)) return json({ ok: false, message: '口令错误' }, 403, CORS);
      if (!d1ok()) return json({ ok: false, message: 'D1 未绑定' }, 503, CORS);
      const day = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(url.searchParams.get('day') || '')
        ? url.searchParams.get('day') : beijingDate();
      const poolQ = url.searchParams.get('pool') || POOL_NAME;
      const rows = await d1All('SELECT uid FROM runs WHERE day=? AND pool=?', [day, poolQ]);
      // 2026-11-06：以前 `|| []` 把「D1 读失败」当成「今天没人播过」→ run.py 会把当天已播的号
      // 再播一遍（11-06 实测同类事故造成 127 个号双播）。读不到就必须显式报错，让客户端重试/
      // 拒绝开跑，绝不能伪装成空名单。
      if (!rows) return json({ ok: false, message: 'D1 查询失败（runs 表读不到，不敢当成空名单）' }, 503, CORS);
      return json({ ok: true, day: day, pool: poolQ, n: rows.length,
                    uids: rows.map(r => String(r.uid)) }, 200, CORS);
    }
    // 单号已跑标记：body {pass,pool,day,uids:[...],slice}
    // 写的是与 /api/snap 完全同一张 runs 表、同一套 UPSERT 语义，
    // 所以「先逐号标记、结束时再整片上报」不会产生重复行，/api/coverage 的实跑口径也不变。
    if (url.pathname === '/api/run_mark' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      const c = await cfg();
      if (!c.assignPass) return json({ ok: false, message: '未配置 ASSIGN_PASS' }, 503, CORS);
      const pass = String(body.pass || '');
      if (pass !== c.assignPass && !(c.adminPass && pass === c.adminPass)) return json({ ok: false, message: '口令错误' }, 403, CORS);
      if (!d1ok()) return json({ ok: false, message: 'D1 未绑定' }, 503, CORS);
      const day = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(body.day || '') ? body.day : beijingDate();
      const poolQ = body.pool || POOL_NAME;
      const uids = Array.isArray(body.uids) ? body.uids.map(x => String(x)).filter(Boolean).slice(0, 300) : [];
      if (!uids.length) return json({ ok: true, wrote: 0 }, 200, CORS);
      const wrote = await d1RunsWrite(day, poolQ, uids, body.slice);
      return json({ ok: true, wrote: wrote }, 200, CORS);
    }
    // 控制台数据聚合：两群账号列表（绝不下发 ck）+ 当日与前日快照（供日环比）
    // ================= 2026-11-06 新增：控制台首屏 KV 缓存 =================
    // 动机：/api/console/data 是首屏只读大查询（索引优化后实测一次 ≈8,200 行 D1 读），
    //   短时间反复刷新只是重复烧额度。缓存 TTL 5 分钟 + 版本号即时失效：
    //   - 没改任何东西时随便刷 = 命中 KV（0 行 D1 读）；
    //   - 登记/编辑/删号/改客服（ccBust）= 版本号更新，下一次刷新立即回源，看不到旧数据；
    //   - 兜底：TTL 300 秒，写钩子没覆盖的变更（播放轮 runs/快照等系统写入）最多延迟 5 分钟可见。
    // 键结构：cc:<版本号>:<权限full/ro>:<结束日>:<起始日> —— 权限与日期区间各自独立缓存。
    // KV 消耗：命中 = 2 读；未命中 = 2 读 + 1 写（免费写额度 1000/天，绰绰有余）。
    // 代价说明：D1 抖动瞬间构建的降级数据也可能被缓存，最多 5 分钟后自愈 ——
    //   用最多 5 分钟的有限陈旧换掉每次刷新 8,200 行读，值得。
    // ⚠ ccBust 绝不要挂进 /api/assign、/api/run_done、/api/snap 等播放轮高频接口：
    //   那会把缓存打成永远未命中，白费这套机制（播放轮的数据更新走 TTL 兜底就够）。
    async function ccBust() {
      try { await POOL.put('cc:ver', String(Date.now())); } catch (e) {}
    }
    // 2026-11-09：把「连续达标天数」单独拎出来缓存。它是首屏最贵的一条查询 ——
    //   snapStreakSQL() 要扫 6 天快照再跑两个窗口函数，实测 4,000~5,600 行读取，
    //   占首屏 D1 读的 50%~70%；可这个数字一天只在 11:40 快照写入后变一次。
    // 缓存 30 分钟（今天）/ 24 小时（历史日期，那几天的快照不会再变）。
    // 代价：新登记的号最多晚 30 分钟才出现在「连续天数」列（它本来也没有历史快照，显示的是 —）。
    async function streakCached(d) {
      if (!d1ok()) return null;
      const isToday = (d === beijingDate());
      const k = 'ccst:' + d;
      // 2026-11-10：同样搬到 Cache API（KV 写额度太贵，这条 30 分钟写一次 = 96 次/天）
      const hit = await caGet(k);
      if (hit) { try { return JSON.parse(hit); } catch (e) {} }
      const rows = await d1All(snapStreakSQL(), [dateMinusN(d, 6), d]).catch(() => null);
      if (rows) { await caPut(k, JSON.stringify(rows), isToday ? 1800 : 86400); }
      return rows;
    }
    if (url.pathname === '/api/console/data' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      const role = await consoleRole(body);
      if (!role) return json({ message: '账号或密码错误' }, 403, CORS);
      const date = /^\d{4}-\d{2}-\d{2}$/.test(body.date || '') ? body.date : beijingDate();
      // 2026-10-27：支持「日期范围」—— 控制台日期框改成「起始 ~ 结束」两个，
      // body.date 仍是结束日（"今天"这一侧，plan/runs/streak/删号等一律按它算），
      // body.prevDate 由前端给起始日；不给就退回「结束日的前一天」（等于原来的单日视图）。
      // 只影响 snap.cur / snap.prev 这两张快照表取哪天，其余字段口径完全不变。
      const prevDate = /^\d{4}-\d{2}-\d{2}$/.test(body.prevDate || '')
        ? (body.prevDate < date ? body.prevDate : dateMinus1(date))
        : dateMinus1(date);
      // 2026-11-06：先查缓存（命中 = 0 行 D1 读，直接回）。body.nocache=1 可强制回源。
      // 2026-11-10：缓存从 KV 搬到 Cache API —— KV 写只有 1000/天，而这里每 5 分钟就写一次，
      //   控制台开着一天能刷掉几百次，是 11-09 KV 写打到 100% 的主要来源之一。
      //   语义不变：命中 0 行 D1 读、版本号即时失效、TTL 按日期分档。
      let _ccSkip = false;
      try { _ccSkip = body.nocache === 1; } catch (e) {}
      let _ccKey = '';
      let _ccTtl = 300;
      let _ccVerOut = '';   // 只用于响应头排障：看 cc:ver 是否在两次请求之间抖动
      if (!_ccSkip) {
        const _ccVer = (await POOL.get('cc:ver').catch(function () { return null; })) || '0';
        _ccVerOut = String(_ccVer);
        _ccKey = 'cc:' + _ccVer + ':' + role + ':' + date + ':' + (prevDate || '');
        // 2026-11-09：按结束日分档。查历史日期时那几天的快照/播放量早已定格，
        // 没必要每 5 分钟重查一遍（一次约 8,200 行）—— 缓存 1 小时。今天仍是 5 分钟。
        if (date !== beijingDate()) _ccTtl = 3600;
        const _ccHit = await caGet(_ccKey);
        if (_ccHit) return new Response(_ccHit, { status: 200, headers: Object.assign({ 'Content-Type': 'application/json' }, CORS, { 'X-Cache': 'hit', 'X-CCVer': _ccVerOut.slice(0, 16) }) });
      }
      // 2026-10-22：控制台是高频只读接口，原来每刷新一次就跑 pruneExpired()（全量重建 +
      // 可能删键 + 写 204KB master + 推 12 个 Secret）。改为直接读 D1 全表（一条 SELECT）。
      // 过期号在页面上仍会按 exp 字段标红，真正的清理交给管理后台/resync。
      //
      // 2026-10-23：并发化。原来这一段是 7 段串行 await（鉴权后的读全池 → 读配置 → 读对端地址
      // → fetch 对端 worker → 读今日快照 → 读昨日快照 → 读时长表），实测业务耗时 1.0~1.75s，
      // 其中大部分是这七段 rtt 相加。这些读彼此没有任何依赖（唯一有依赖的是「拉对端账号列表」
      // 需要 cfg().groupPass，单独放在下面），一次 Promise.all 全部发出去即可。
      // 并发不会打爆 D1/KV：每一段都是单条 SELECT 或单键 get。
      // 2026-10-23 第五批（运行状态上控制台，纯加法不改现有字段）：
      //   plan      → buildPlan(date) 拿当天应跑名单（与 /api/coverage 同一口径：plans=listeners）
      //   ranRows   → runs 表实跑名单
      //   deadRows  → D1 dead_log 最近删号记录
      //   suspectRows → accounts.suspect_at!='' 的待复核号（注意空串不是 NULL，不能写 IS NOT NULL）
      //   freshRows → 各池当天快照最后写入时间（数据新鲜度）
      //   actions   → 两仓库最近一次 run.yml 作业状态（fetchActionsStatus 内部带 KV 5 分钟缓存）
      // 2026-11-06：song_meta / acc_meta 两张字典表改成一次 KV 缓存读（TTL 15 分钟）。
      // 原来每次首屏各全表扫一遍（815 + 795 = 1,610 行），而这两张表一天才变一两次。
      // 必须在 Promise.all 之前建好这个 promise，否则下面两个位置会各查一次 D1（缓存也救不了）。
      const _metaP = d1ok() ? metaDicts() : Promise.resolve(null);
      const [master, c2, cur, prev, old, dr, peerUrlRaw, plan, ranRows, deadRows, suspectRows, freshRows, actions, streakRows, songRows, accRows, noticeRows, deadTodayRows, regCfgNow, planSnaps] = await Promise.all([
        mergePool(),
        cfg(),
        readSnapDay(date),
        readSnapDay(prevDate),
        // 2026-11-07：14 天前快照 —— 给「今日零增长 / 净增≤0」标记算两周平均日增与回吐估算。
        // 只在 KV 缓存（TTL 5 分钟）未命中时跑这一次 SELECT（约 700 行 = 免费额度的 0.014%），命中时 0 开销。
        readSnapDay(dateMinusN(date, 14)),
        d1ok() ? d1All('SELECT pool,uid,dur FROM durs') : Promise.resolve(null),
        POOL.get('PEER_URL').catch(() => null),
        buildPlan(date).catch(() => null),
        d1ok() ? d1All('SELECT pool,uid FROM runs WHERE day=?', [date]).catch(() => null) : Promise.resolve(null),
        d1ok() ? d1All('SELECT pool,uid,name,reason,at FROM dead_log ORDER BY at DESC LIMIT 12').catch(() => null) : Promise.resolve(null),
        d1ok() ? d1All("SELECT pool,uid,name,suspect_at,relogin_at FROM accounts WHERE suspect_at!='' ORDER BY suspect_at DESC").catch(() => null) : Promise.resolve(null),
        d1ok() ? d1All('SELECT pool,MAX(at) AS last FROM snapshots WHERE day=? GROUP BY pool', [date]).catch(() => null) : Promise.resolve(null),
        fetchActionsStatus(),
        // 2026-10-23：最近 7 天快照，用于「连续不涨天数」。date-6 起（含当天）；
        // 改造前数据断层天的行不存在，calcStreaks 天然跳过。
        // 2026-11-06：改成在 SQL 里算，不再把 7 天快照整批拉回 JS。
        //   原来每次首屏拉 4,071 行回来只为了算出一个 {uid: 天数} 的小字典，现在最多回 704 行。
        //   口径与原 calcStreaks 逐条比对过（6 个日期 hz+dz 全量 + 8 组边界用例，100% 一致）。
        // 2026-11-09：再包一层 KV 缓存（streakCached），命中时这一条 4,000+ 行的查询直接跳过。
        streakCached(date),
        // 2026-10-25：歌曲/账号元数据（song_meta / acc_meta，由 tmp/sync_song_meta.py 回填）。
        // 用来判断「共创歌曲（合唱）」「绑错歌（歌曲作者里没有本人音乐人）」这两类售后问题。
        // 纯只读、失败降级为 null，缺数据时页面只是不打这两个标签，不影响其它列。
        // 2026-11-06：走同一个 _metaP（KV 缓存 15 分钟），两个位置共用一次读。
        _metaP.then(m => (m && m.songs) || null),
        _metaP.then(m => (m && m.acc) || null),
        // 2026-10-26：手动删号的「通知号主」判定状态（dead_notice），只用于在删号记录里
        // 标一行「已通知 / 已回池不发 / 待判」。纯只读，失败降级为 null。
        d1ok() ? d1All('SELECT pool,uid,removed_at,state,sent_at,skip_reason FROM dead_notice ORDER BY removed_at DESC LIMIT 60').catch(() => null) : Promise.resolve(null),
        // 2026-10-26：当日删除全量（不受上面 LIMIT 12 限制），只取 uid/pool 用于
        // 「当日删号」口径判定 —— 删完又登记回来的号不该算成删号。
        // 用 substr 精确匹配那一天：控制台可以切到历史日期，写 at>=date 会把之后几天也算进来。
        d1ok() ? d1All('SELECT pool,uid,reason FROM dead_log WHERE substr(at,1,10)=?', [date]).catch(() => null) : Promise.resolve(null),
        // 2026-10-27：客服名单 + 套餐档位（控制台据此生成筛选下拉、套餐汇总与编辑弹窗选项）。
        // 与上面几段一起并发发出，不额外增加一次串行 rtt。
        regCfg().catch(() => REG_CFG_DEFAULT),
        // 2026-11-09：当轮 plan 名单快照（两池各一行），coverage 口径用，见 planSnapPut。
        planSnapAll(date).catch(() => null),
      ]);
      const disp = e => ({
        name: e.name || '', uid: e.uid != null ? String(e.uid) : '',
        song: e.song != null ? String(e.song) : '', added: e.added || '',
        email: e.email || '', phone: e.phone || '', noListen: !!e.noListen, exp: e.exp || '',
        // 2026-10-27：客服标签 + 套餐档位（控制台新增两列 / 顶部套餐汇总 / 按客服筛选的数据源）
        agent: e.agent || '', plan: e.plan || '',
        // 2026-11-01：公益号（只帮别人听，自己的歌不进互听环，不签到）
        pub: !!e.pub,
        // 2026-11-05：备注（存在 D1 的 note 列）+ 补号标记。
        // 前端据此渲染「备注」列和「补」标签，也是编辑弹窗回填的初值。
        note: e.note || '', rb: !!e.rb, rbFrom: Number(e.rbFrom) || 0, rbStart: e.rbStart || '',
      });
      const hz = master.map(disp);
      // 定制群账号列表：实时向对端 worker 拉（对穿口令；拉失败不阻塞主群展示）
      // ⚠️ 对穿方向：本 worker 的 PEER_PASS 键存的是「定制群口令」，而定制群 worker 的 PEER_PASS 键
      //    存的是「本群口令」——所以调对端接口要用本群群口令 c.groupPass，不是本 worker 的 PEER_PASS。
      let dz = [];
      try {
        const peerUrl = cleanKV(peerUrlRaw) || PEER_DEFAULT;
        // 2026-10-26：优先用独立对穿口令 PEER_KEY；未配置才回退「本群群口令」的老对穿方式。
        const pk = await peerKey();
        const dzPass = pk || c2.groupPass;
        if (dzPass) {
          const r = await fetch(peerUrl.replace(/\/+$/, '') + '/api/peer/pool?pass=' + encodeURIComponent(dzPass), { headers: { 'User-Agent': 'cron-relay-worker' } });
          const d = await r.json();
          if (d && d.ok) dz = (d.entries || []).map(disp);
        }
      } catch (e) { /* 对端不可达：dz 列表留空，页面会提示 */ }
      // 2026-10-22 第三批：D1 可用时不再读 KV 的 console:durs（省一次读，也不会读到旧值）。
      // 只有 D1 不可用时才回退 KV —— 那份现在已经只在 D1 写失败时才会被更新。
      let durs = {};
      if (dr) {
        // 2026-10-23：durs 表主键是 (pool,uid)，同一个号可能同时挂在两个群（实测 7 个），
        // 之前只按 uid 拍平会让两池互相覆盖 → 时长显示成另一个群那首歌的。现在额外写一份
        // 带池前缀的键「hz|uid」，页面优先用它；扁平键保留，兼容老页面与 KV 回退模式。
        for (const r of dr) {
          if (!r.uid || r.dur == null) continue;
          const v = Number(r.dur) || 0;
          const uid = String(r.uid);
          durs[(r.pool === 'dz' ? 'dz' : 'hz') + '|' + uid] = v;
          if (!(uid in durs)) durs[uid] = v;
        }
      } else {
        try { durs = JSON.parse(await POOL.get('console:durs') || '{}'); } catch (e) {}
      }
      // 2026-10-26 新增：furtherVipGetTime 留档（键 'hz|uid' / 'dz|uid' → YYYY-MM-DD）。
      // 只在 slice=am 补采时写入；读失败降级 null。⚠️ 仅数据留档，不参与任何判定
      //（实测它不是当前周期结束日，详见 /api/snap 处说明）。
      let periods = null;
      try { periods = JSON.parse(await POOL.get('console:period') || 'null'); } catch (e) { periods = null; }
      // ---- 2026-10-23 组装运行状态数据（纯加法：全部是新键，不影响 hz/dz/durs/snap）----
      // coverage：应跑 vs 实跑。
      // 2026-11-09：口径改成「当轮 plan 快照」优先 —— expected 取本轮首轮 plan 落地的名单，
      // 与 /api/coverage 完全一致；没有快照（老日期 / D1 读不到）时回退实时 buildPlan。
      const cov = {};
      if (Array.isArray(ranRows) || (plan && plan.ok && Array.isArray(plan.plans))) {
        const ranByPool = {};
        for (const r of (ranRows || [])) {
          const p = r.pool === 'dz' ? 'dz' : 'hz';
          (ranByPool[p] = ranByPool[p] || new Set()).add(String(r.uid));
        }
        for (const p of ['hz', 'dz']) {
          const sn = (planSnaps && planSnaps[p]) || null;
          let exp = null, srcp = '';
          if (sn) { exp = sn.uids; srcp = 'snap'; }
          else if (plan && plan.ok && Array.isArray(plan.plans)) {
            exp = plan.plans.filter(x => x.pool === p).map(x => String(x.uid)); srcp = 'live';
          }
          if (!exp || !exp.length) continue;
          const ranSet = ranByPool[p] || new Set();
          const missing = exp.filter(u => !ranSet.has(u));
          cov[p] = { expected: exp.length, ran: exp.length - missing.length,
                     missing_n: missing.length,
                     missing: missing.slice(0, 80),
                     src: srcp, snap_at: sn ? sn.at : '',
                     pct: exp.length ? Math.round((exp.length - missing.length) * 1000 / exp.length) / 10 : 0 };
        }
      }
      // 2026-10-26：通知状态索引（按「池|uid」取最近一条判定）。只覆盖手动删号；
      // cookie_invalid 的号由 run.py 当场发信，不进这张表。
      const noticeMap = {};
      for (const r of (noticeRows || [])) {
        const k = (r.pool === 'dz' ? 'dz' : 'hz') + '|' + String(r.uid || '');
        if (!noticeMap[k]) noticeMap[k] = { state: r.state || '', removed_at: r.removed_at || '', sent_at: r.sent_at || '', why: r.skip_reason || '' };
      }
      const dead = (deadRows || []).map(r => ({ pool: r.pool === 'dz' ? 'dz' : 'hz', uid: String(r.uid || ''),
                                                name: r.name || '', reason: r.reason || '', at: r.at || '',
                                                notice: noticeMap[(r.pool === 'dz' ? 'dz' : 'hz') + '|' + String(r.uid || '')] || null }));
      // 2026-11-04：多带一个 relogin —— 非空 = 已经给号主发过「请重新登记」，正在等他自己处理。
      // 页面上要能区分「刚判出来的待复核」和「通知了但一直没人管」，否则看不出卡了多久。
      const suspects = (suspectRows || []).map(r => ({ pool: r.pool === 'dz' ? 'dz' : 'hz', uid: String(r.uid || ''),
                                                       name: r.name || '', since: r.suspect_at || '',
                                                       relogin: r.relogin_at || '' }));
      // 2026-10-26：当日删除明细（用于「当日删号」统计）。只给 uid/pool/reason，
      // 前端拿当前号池做差集 —— 还在池里的算「已回池」（迁移/重登），不算真删。
      const deadToday = (deadTodayRows || []).map(r => ({ pool: r.pool === 'dz' ? 'dz' : 'hz',
                                                          uid: String(r.uid || ''), reason: r.reason || '' }));
      const fresh = {};
      for (const r of (freshRows || [])) { fresh[r.pool === 'dz' ? 'dz' : 'hz'] = r.last || ''; }
      // 2026-10-23：连续不涨天数（>=2 天才有条目；查询失败时降级为空字典，页面无标记）
      // 2026-11-06：SQL 已经把天数算好（[{pool,uid,streak}]），这里只做形状转换。
      //   输出结构不变：{ hz:{ uid: 天数 }, dz:{ ... } }，前端 DATA.streak[pool][uid] 照旧。
      const streak = { hz: {}, dz: {} };
      for (const r of (streakRows || [])) {
        if (!r || r.uid == null) continue;
        const _sp = (r.pool === 'dz') ? 'dz' : 'hz';
        const _sn = Number(r.streak) || 0;
        if (_sn >= 2) streak[_sp][String(r.uid)] = _sn;
      }
      // 2026-11-05 新增：对「快照里 650 是 0% 但近30日播放 ≥650」的号实时复核一次（KV 缓存 30 分钟）。
      // 只写 snap.cur[pool][uid].lr / .lp 两个新键，不动 rate —— 其它列、顶部统计、周报口径全部不变。
      // 候选上限 40：正常情况下这批号只有十几个（11-05 实测 12 个），超了说明口径异常，宁可不查也不打爆网易。
      try {
        const cands = [];
        for (const p2 of ['hz', 'dz']) {
          const m2 = (cur && cur[p2]) || {};
          for (const uid of Object.keys(m2)) {
            const a2 = m2[uid];
            if (a2 && a2.rate === 0 && a2.rpc30 != null && a2.rpc30 >= 650) cands.push({ pool: p2, uid: String(uid) });
          }
        }
        if (cands.length && cands.length <= 40) {
          const lv = await live650Batch(cands);
          for (const p2 of ['hz', 'dz']) {
            const m2 = (cur && cur[p2]) || {};
            for (const uid of Object.keys(m2)) {
              const v = lv[uid];
              if (!v) continue;
              m2[uid].lr = v.r == null ? null : v.r;
              m2[uid].lp = v.p == null ? null : v.p;
            }
          }
        }
      } catch (e) { console.error('650 实时复核失败（不影响控制台其余数据）:', e && e.message); }
      // 2026-10-25：歌曲作者归属（控制台「共创歌曲 / 绑错歌」标签的数据源）
      // songs[song] = {n:作者数, i:[作者id...], f:第一艺人名, g:1=网易查无此歌}
      // artists[uid] = [音乐人id, 音乐人名]；id 为 '' 表示确认该账号不是音乐人
      const songs = {};
      for (const r of (songRows || [])) {
        if (!r || r.song == null) continue;
        // 2026-11-11：ns = 全部歌手名（原来只给 id 数组和第一艺人名，控制台要对「歌手 vs 音乐人同名」人肉核对没有原料）
        let ids = [], nms = [];
        try {
          const _arr = (JSON.parse(r.artists || '[]') || []);
          ids = _arr.map(x => String((x && x[0] != null) ? x[0] : ''));
          nms = _arr.map(x => String((x && x[1]) || ''));
        } catch (e) { ids = []; nms = []; }
        songs[String(r.song)] = { n: Number(r.n_artists) || 0, i: ids, ns: nms, f: r.first_artist || '', g: Number(r.gone) ? 1 : 0 };
      }
      const artists = {};
      for (const r of (accRows || [])) {
        if (!r || r.uid == null) continue;
        artists[String(r.uid)] = [r.artist_id == null ? '' : String(r.artist_id), r.artist_name || ''];
      }
      // 2026-10-25：顺手在后台补几条歌曲/账号元数据（新号登记后自动补，不用再手动跑脚本）
      try { if (globalThis.CTX && typeof globalThis.CTX.waitUntil === 'function') globalThis.CTX.waitUntil(backfillMeta()); } catch (e) {}
      // 2026-11-05：只读口令不给「日志」入口（运行状态横条里的 GitHub Actions 链接）。
      // 运行日志页面里有失败分片的账号 uid、接口报错等内部排障信息，只读给的是客服/外部视角。
      // 这里在服务端就把 url 抹成空串，不是只在前端隐藏 —— 只读拿同一把口令直接 POST
      // /api/console/data（或改页面 DOM）也拿不到链接。满权限（role==='full'）原样返回。
      const actionsOut = (actions || []).map(function (x) {
        if (!x || role === 'full') return x;
        return Object.assign({}, x, { url: '' });
      });
      const _out = { ok: true, date: date, prevDate: prevDate, oldDate: dateMinusN(date, 14), hz: hz, dz: dz, durs: durs, snap: { cur: cur, prev: prev, old: old },
                    coverage: cov, actions: actionsOut, dead: dead, deadToday: deadToday, suspects: suspects, fresh: fresh,
                    streak: streak, songs: songs, artists: artists, periods: periods,
                    // 2026-10-27：role 决定页面要不要把写入口关掉；cfg 供筛选下拉与编辑弹窗用
                    // 2026-11-09：今晚每号要听几首（供「运行状态」横条显示）。plan 上面已经算过，
                    // 这里只是把已有字段搬出来 —— **不新增任何 D1 / KV 读**，且随首屏 KV 缓存一起命中。
                    run: (plan && plan.ok) ? { p: plan.p, m: plan.m, l: plan.l,
                           perDay: (plan.accel || {}).perDay || 0, days: (plan.accel || {}).days || 0,
                           capped: (plan.accel || {}).capped ? 1 : 0, max: (plan.accel || {}).max || 0,
                           slots: (plan.accel || {}).slots || 0 } : null,
                    role: role, cfg: regCfgNow };
      const _body = JSON.stringify(_out);
      // 2026-11-06：首屏结果写入缓存（TTL 5 分钟）。命中时上面整段大查询都不会再跑。
      // 2026-11-09：TTL 按日期分档（今天 300s / 历史 3600s），见上面 _ccTtl。
      // 2026-11-10：落 Cache API（不占 KV 写额度）；失败无妨，下一刷重建。
      // 2026-11-10 晚：把 put 的结果带到 X-Cache 头里（miss-stored / miss-storefail）。
      //   起因：实测连续 4 次请求全是 miss、每次都跑满 10 秒全量查询 —— 说明这份缓存从来没命中过，
      //   需要区分「写失败」（Cache API 拒收 818KB 响应？）和「key 不一致」（cc:ver 抖动）。
      let _ccPutOk = false;
      if (!_ccSkip && _ccKey) { _ccPutOk = await caPut(_ccKey, _body, _ccTtl); }
      return new Response(_body, { status: 200, headers: Object.assign({ 'Content-Type': 'application/json' }, CORS, {
        'X-Cache': _ccSkip ? 'bypass' : (_ccPutOk ? 'miss-stored' : 'miss-storefail'),
        'X-CCVer': _ccVerOut.slice(0, 16),
        'X-CAPut': _caPutOk + '/' + _caPutN,
        'X-CAErr': String(_caLastErr || '').slice(0, 80) }) });
    }
    // 控制台编辑：hz 本地执行（与管理后台同一套逻辑）；dz 转发到对端 worker 的对等接口
    if (url.pathname === '/api/console/entry' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      // 2026-10-27：写接口只认满权限口令（只读口令进来这里一律 403）
      if (!(await consoleAuthFull(body))) {
        const who = await consoleRole(body);
        return json({ message: who === 'ro' ? '当前是只读口令，不能修改账号' : '账号或密码错误' }, 403, CORS);
      }
      if (body.pool === 'dz') {
        try {
          const c3 = await cfg();
          // 2026-10-26：优先用独立对穿口令 PEER_KEY；未配置才回退「本群群口令」的老对穿方式。
          const peerUrl = (cleanKV(await POOL.get('PEER_URL')) || PEER_DEFAULT).replace(/\/+$/, '');
          const fwdPass = (await peerKey()) || c3.groupPass;
          if (!fwdPass) return json({ message: '本 worker 未配置对穿口令（KV 键 PEER_KEY / GROUP_PASS），无法编辑定制群账号' }, 503, CORS);
          const fwd = { pass: fwdPass, action: body.action, uid: body.uid, name: body.name,
            ck: body.ck, link: body.link, email: body.email, exp: body.exp, noListen: body.noListen,
            agent: body.agent, plan: body.plan,
            // 2026-11-05：备注 / 补号标记也要转发，否则在控制台给定制群的号打补号标会静默无效
            note: body.note, rb: body.rb, rbStart: body.rbStart, rbFrom: body.rbFrom };
          const r = await fetch(peerUrl + '/api/peer/entry', { method: 'POST',
            headers: { 'Content-Type': 'application/json', 'User-Agent': 'cron-relay-worker' },
            body: JSON.stringify(fwd) });
          // 2026-11-06：定制群的号同样显示在控制台首屏 —— 编辑成功也要作废首屏缓存
          try { if (r.status === 200) await ccBust(); } catch (e) {}
          return new Response(r.body, { status: r.status, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
        } catch (e) {
          return json({ message: '转发到定制群失败：' + ((e && e.message) || e) }, 502, CORS);
        }
      }
      return applyEntryEdit(body);
    }
    // 客服名单 / 套餐档位维护（2026-10-27）：只认满权限口令。
    // 只传要改的字段：agents 和 plans 哪个没传就保持原样，避免「只加一个人把套餐表冲掉」。
    if (url.pathname === '/api/console/cfg' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      if (!(await consoleAuthFull(body))) {
        const who = await consoleRole(body);
        return json({ message: who === 'ro' ? '当前是只读口令，不能修改客服名单' : '账号或密码错误' }, 403, CORS);
      }
      const cur = await regCfg();
      const next = {
        agents: body.agents !== undefined ? body.agents : cur.agents,
        plans: body.plans !== undefined ? body.plans : cur.plans,
        // 2026-11-06：售后群号。前端把「客服名|群号」解析后分开传；没传就保持原样，
        //   避免「只改套餐把群号冲掉」。
        groups: body.groups !== undefined ? body.groups : cur.groups,
        default_group: body.default_group !== undefined ? body.default_group : cur.default_group,
      };
      const saved = await saveRegCfg(next);
      // 2026-11-06：改名提示。在名单框里把一个字改掉，系统分不清这是「改名」还是
      //   「删掉一个客服 + 新增一个客服」—— 但两者后果完全不同：改名要连历史号和结算账本一起换，
      //   删加只换登记下拉。这里只做提示、绝不擅自改数据，真正的改名走 /api/console/agent_rename。
      const goneA = (cur.agents || []).filter(a => !(next.agents || []).includes(a));
      const addA = (next.agents || []).filter(a => !(cur.agents || []).includes(a));
      const withGrp = Object.keys(saved.cfg.groups || {}).length;
      const hint = (goneA.length && goneA.length === addA.length)
        ? '；⚠ 检测到「' + goneA.join('、') + '」被「' + addA.join('、') + '」替换 —— 如果是改名，请用「客服改名」，否则已登记的号和结算账本仍是旧名字'
        : '';
      try { await ccBust(); } catch (e) {}
      return json({ ok: true, d1: saved.ok, cfg: saved.cfg,
        message: '已保存：客服 ' + saved.cfg.agents.length + ' 人（' + withGrp + ' 人配了售后群）、套餐 ' + saved.cfg.plans.length + ' 档'
          + (saved.ok ? '' : '（⚠️ D1 写入失败，已写 KV 兜底，请稍后重试）') + hint }, 200, CORS);
    }
    /* ===== 2026-11-10：客服机器授权（控制台「设备授权」）=====
       D1 reg_devices 是权威，KV dev:<机器码> 是兜底镜像（D1 读额度打满时用）。
       只认满权限口令，只读口令进不来。 */
    if (url.pathname === '/api/console/dev_list' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      if (!(await consoleAuthFull(body))) {
        const who = await consoleRole(body);
        return json({ message: who === 'ro' ? '当前是只读口令，不能管理设备' : '账号或密码错误' }, 403, CORS);
      }
      const rows = await d1All('SELECT dev,agent,quota,state,note,ctime,last_at FROM reg_devices ' +
                               'ORDER BY ctime DESC LIMIT 300');
      if (rows === null) return json({ ok: false, message: '数据库读不到（' + d1ErrHint() + '）' }, 503, CORS);
      return json({ ok: true, rows: rows }, 200, CORS);
    }
    if (url.pathname === '/api/console/dev_save' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      if (!(await consoleAuthFull(body))) {
        const who = await consoleRole(body);
        return json({ message: who === 'ro' ? '当前是只读口令，不能管理设备' : '账号或密码错误' }, 403, CORS);
      }
      const dev = regDevNorm(body.dev);
      if (dev.length < 6) return json({ message: '机器码格式不对（应该是 12 位字母数字，来自客服软件弹出的那串）' }, 400, CORS);
      const stRaw = String(body.state || 'ok');
      const state = (stRaw === 'hold' || stRaw === 'pending') ? stRaw : 'ok';
      const quota = Math.max(1, Math.min(2000, Number(body.quota) || 200));
      const agent = normAgent(body.agent);
      const note = String(body.note || '').slice(0, 60);
      const now = regIso(Date.now());
      const ex = await d1All('SELECT dev,ctime FROM reg_devices WHERE dev=? LIMIT 1', [dev]);
      if (ex === null) return json({ ok: false, message: '数据库读不到（' + d1ErrHint() + '）' }, 503, CORS);
      let ok;
      if (ex.length) {
        ok = await d1Run('UPDATE reg_devices SET agent=?, quota=?, state=?, note=? WHERE dev=?',
                         [agent, quota, state, note, dev]);
      } else {
        ok = await d1Run('INSERT INTO reg_devices (dev,agent,quota,state,note,ctime,last_at) VALUES (?,?,?,?,?,?,?)',
                         [dev, agent, quota, state, note, now, '']);
      }
      if (!ok) return json({ ok: false, message: '保存失败（' + d1ErrHint() + '）' }, 503, CORS);
      /* KV 镜像：非关键路径。写失败（额度满）只影响「D1 读满时还能不能校验这一台」，不影响本次保存。 */
      let kvok = true;
      try {
        await POOL.put('dev:' + dev, JSON.stringify({
          dev: dev, agent: agent, quota: quota, state: state, note: note,
          ctime: (ex.length && ex[0] && ex[0].ctime) || now, last_at: '' }));
      } catch (e) { kvok = false; }
      return json({ ok: true, kv: kvok,
        message: '已保存' + (kvok ? '' : '（⚠️ KV 镜像没写进去，可能是今日 KV 写额度满了；不影响现在生效，但 D1 读满时会退回到未授权）') },
        200, CORS);
    }
    if (url.pathname === '/api/console/dev_del' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      if (!(await consoleAuthFull(body))) {
        const who = await consoleRole(body);
        return json({ message: who === 'ro' ? '当前是只读口令，不能管理设备' : '账号或密码错误' }, 403, CORS);
      }
      const dev = regDevNorm(body.dev);
      if (!dev) return json({ message: '机器码不能为空' }, 400, CORS);
      const n = await d1Changes('DELETE FROM reg_devices WHERE dev=?', [dev]);
      if (n < 0) return json({ ok: false, message: '删除失败（' + d1ErrHint() + '）' }, 503, CORS);
      try { await POOL.delete('dev:' + dev); } catch (e) {}
      return json({ ok: true, message: n ? '已删除这台设备的授权' : '没找到这台设备' }, 200, CORS);
    }
    // ================= 客服改名（2026-11-06 新增）=================
    // 需求：客服名在库里其实存了三份 —— reg_cfg.agents（登记下拉）、accounts.agent（每个号的归属）、
    //   ledger.agent（每一笔成交）。只在名单框里改字，后两份照旧是旧名，于是控制台表格和月度结算
    //   全都还是旧名字；而且从操作上根本看不出这是「改名」还是「删掉一个 + 新增一个」。
    //   这里给一个显式入口：一次把三份全部换掉，并回报改了多少个号、多少笔订单。
    // 消耗（重要提醒）：两条 UPDATE 各是一次全表扫描 —— accounts ~700 行 + ledger ~820 行，
    //   合计约 1,500 行读 + 200 行写，是「改一次」的一次性成本，改完不会有任何持续开销。
    //   免费额度 500 万行读 / 10 万行写 每天，一次改名约占 0.03%，可以放心用；
    //   但**绝不要**把它挂进任何定时任务 —— 那才是唯一会天天吃额度的做法。
    if (url.pathname === '/api/console/agent_rename' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      if (!(await consoleAuthFull(body))) {
        const who = await consoleRole(body);
        return json({ message: who === 'ro' ? '当前是只读口令，不能改客服名' : '账号或密码错误' }, 403, CORS);
      }
      const oldN = normAgent(body.old);
      const newN = normAgent(body.new);
      const newRaw = String(body.new == null ? '' : body.new).trim();
      if (!oldN || !newN) return json({ message: '旧名字和新名字都不能为空' }, 400, CORS);
      if (oldN === newN) return json({ message: '新旧名字一样，不用改' }, 400, CORS);
      // normAgent 会把超长/带非法字符的名字悄悄截断，那会让用户以为改成功了其实名字变了样
      if (newRaw && newN !== newRaw) {
        return json({ message: '新名字不合法：最长 16 个字，且不能含引号、尖括号和换行' }, 400, CORS);
      }
      if (!d1ok()) return json({ message: 'D1 没绑定，现在改不了（等 D1 恢复再试）' }, 503, CORS);
      // ② 已登记的号 + ③ 成交账本。不带 pool 条件：主群、定制群一起改（同一个 D1 库）。
      //    先动数据再动名单：万一 D1 写失败，名单还是旧名，用户重试即可，不会出现「下拉变了数据没变」。
      const nAcc = await d1Changes('UPDATE accounts SET agent=? WHERE agent=?', [newN, oldN]);
      const nLed = await d1Changes('UPDATE ledger SET agent=? WHERE agent=?', [newN, oldN]);
      if (nAcc < 0 || nLed < 0) {
        return json({ ok: false, message: '写 D1 失败（' + (_d1LastErr || 'D1 异常') + '），这次没有改动，请稍后重试。' }, 500, CORS);
      }
      // ① 名单：只有旧名确实还在名单里时才替换（位置不变、不重排），
      //    旧名不在名单（比如之前被删掉、只剩历史数据）就只改数据、不碰名单 ——
      //    绝不把新名字硬塞进名单，那等于顺手替用户新加了一个客服（2026-11-06 自测踩到过）。
      const cur = await regCfg();
      const inList = cur.agents.includes(oldN);
      if (!inList && nAcc === 0 && nLed === 0) {
        return json({ message: '没找到叫「' + oldN + '」的客服：名单里没有，也没有挂在它名下的号或订单。刷新页面确认一下现在的名字。' }, 400, CORS);
      }
      let saved = { ok: true, cfg: cur };
      if (inList) {
        const ag = [];
        for (const a of cur.agents) {
          if (a === oldN) { if (!ag.includes(newN)) ag.push(newN); }
          else if (!ag.includes(a)) ag.push(a);
        }
        if (!ag.includes(newN)) ag.push(newN);
        // 2026-11-06：群号跟着名字走（改名不改群号，只换键）。
        const gp = {};
        for (const k of Object.keys(cur.groups || {})) {
          gp[k === oldN ? newN : k] = cur.groups[k];
        }
        saved = await saveRegCfg({ agents: ag, plans: cur.plans, groups: gp, default_group: cur.default_group });
      }
      // 号池快照是 D1 的重建缓存，顺手刷一份，免得 D1 抖动走 KV 兜底时又看到旧名
      try { await refreshPoolSnap(); } catch (e) {}
      try { await ccBust(); } catch (e) {}
      return json({ ok: true, d1: saved.ok, cfg: saved.cfg,
        renamed: { accounts: nAcc, ledger: nLed },
        message: '已改名「' + oldN + '」→「' + newN + '」：账号 ' + nAcc + ' 个、结算订单 ' + nLed + ' 笔'
          + (inList ? '' : '（名单里本来就没有它，只改了历史数据）')
          + (saved.ok ? '' : '（⚠️ 名单写 D1 失败，已写 KV 兜底，请稍后重试）') }, 200, CORS);
    }
    // ================= 记账（2026-11-05 新增）=================
    // 需求：客服按登记单数拿提成，掉线补的号不给提成；每月结清、次月 15 号结算，
    //   所以「12 月回头查 11 月一共多少钱」必须能一次算出来，且不受后续删号/改套餐影响。
    // 数据源是 ledger 成交流水（不是 accounts 当前状态）。
    // ⚠ 只认满权限口令：只读口令是给客服用的，绝不能让他们看到全群营收和各客服金额。
    if (url.pathname === '/api/console/ledger' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      if (!(await consoleAuthFull(body))) {
        const who = await consoleRole(body);
        return json({ message: who === 'ro' ? '当前是只读口令：结算金额只对群主开放' : '账号或密码错误' }, 403, CORS);
      }
      if (!d1ok()) return json({ message: 'D1 不可用，暂时读不到账本' }, 503, CORS);
      const month = String(body.month || '').slice(0, 7);
      if (!/^\d{4}-\d{2}$/.test(month)) return json({ message: '请选择月份（YYYY-MM）' }, 400, CORS);
      const poolF = (['hz', 'dz'].indexOf(String(body.pool || '')) >= 0) ? String(body.pool) : '';
      // 2026-11-05：加「客服」筛选。__none__ = 没有客服归属的历史单。
      // 选中客服后所有汇总/明细都只算这个人，不再挂一个全群总数（否则很容易看错行）。
      const agentRaw = String(body.agent == null ? '' : body.agent).trim();
      const whereBase = ['day>=?', 'day<=?'];
      const paramsBase = [month + '-01', month + '-31'];
      if (poolF) { whereBase.push('pool=?'); paramsBase.push(poolF); }
      const WH = whereBase.join(' AND ');
      const where = whereBase.slice();
      const params = paramsBase.slice();
      if (agentRaw === '__none__') where.push("(agent IS NULL OR agent='')");
      else if (agentRaw) { where.push('agent=?'); params.push(agentRaw); }
      const W = where.join(' AND ');
      // 2026-11-05 晚：下面的 ghost 聚合改成 LEFT JOIN accounts，两张表都有 pool / agent 列，
      // 那份 WHERE 必须带表别名（l.），所以单独拼一套；参数顺序与上面完全一致，直接复用 params。
      const whereL = ['l.day>=?', 'l.day<=?'];
      if (poolF) whereL.push('l.pool=?');
      if (agentRaw === '__none__') whereL.push("(l.agent IS NULL OR l.agent='')");
      else if (agentRaw) whereL.push('l.agent=?');
      const WL = whereL.join(' AND ');
      // 统计口径：money 只累加「非补号 + 已定价」，unpriced 单独计数（不当 0 元混进合计）
      // 2026-11-05：增 giftCnt —— 名字带 name: / manual: / 公益 的是公益赠号或手动加的号，
      //   客户没为它付钱，必须从「有效单」里剔出去单列，否则提成被免费号抬高。
      //   同时 unpriced 排除这类号：公益号没价格是正常的，不该显示成「待补价」诱导去定价。
      const GIFT = "(name LIKE 'name:%' OR name LIKE 'manual:%' OR name LIKE '%公益%')";
      const AGG = "COUNT(*) cnt, SUM(CASE WHEN rb=1 THEN 1 ELSE 0 END) rbCnt, " +
        "SUM(CASE WHEN " + GIFT + " THEN 1 ELSE 0 END) giftCnt, " +
        "SUM(CASE WHEN rb=0 AND price IS NOT NULL THEN price ELSE 0 END) money, " +
        "SUM(CASE WHEN rb=0 AND price IS NULL AND NOT " + GIFT + " THEN 1 ELSE 0 END) unpriced";
      const [byPlan, byAgent, byPool, bySrc, rows, cfgNow, byAgentAll, accRows, ghost] = await Promise.all([
        d1All('SELECT plan, ' + AGG + ' FROM ledger WHERE ' + W + ' GROUP BY plan ORDER BY cnt DESC', params),
        d1All('SELECT agent, ' + AGG + ' FROM ledger WHERE ' + W + ' GROUP BY agent ORDER BY cnt DESC', params),
        d1All('SELECT pool, ' + AGG + ' FROM ledger WHERE ' + W + ' GROUP BY pool', params),
        // 2026-11-10：按「登记类型」分组（src）。老数据 src 全是 'reg'，统计时归到「新登记」。
        d1All('SELECT src, ' + AGG + ' FROM ledger WHERE ' + W + ' GROUP BY src', params),
        d1All('SELECT id,pool,uid,name,agent,plan,price,day,start,exp,rb,rb_from,remark,src FROM ledger WHERE ' +
              W + ' ORDER BY rb, day DESC, id DESC LIMIT 1200', params),
        regCfg().catch(() => REG_CFG_DEFAULT),
        // 下拉框要用「这个人之外还有谁」，所以客服列表不带 agent 过滤
        d1All('SELECT agent, COUNT(*) cnt FROM ledger WHERE ' + WH + ' GROUP BY agent ORDER BY cnt DESC', paramsBase),
        // 号在不在：用来给明细打「号已删」，并统计对账差额（账本只增不改，删号不会抹掉成交）
        d1All('SELECT uid FROM accounts' + (poolF ? ' WHERE pool=?' : ''), poolF ? [poolF] : []),
        // 2026-11-05：号在池 / 号已删 两个金额口径。
        // 为什么用 SQL 聚合而不是拿下面 rows 在 JS 里累加：明细有 LIMIT 1200，
        // 单月单量一旦超过就会被截断，金额会静默算少。这里的聚合直接对全表算，不受截断影响。
        // 注意 accounts 里已过期的号仍然在表内（11-05 起到期不删、降公益），
        // 所以「号已删」严格等于「accounts 里查不到这个 uid」，与池里的明细标记口径一致。
        // ⚠ 2026-11-05 晚改成 LEFT JOIN（原来是 4 个 NOT EXISTS 相关子查询）：
        //   accounts 的主键是 (pool,uid)、没有单独的 uid 索引，`WHERE a.uid=l.uid` 用不上索引，
        //   每个子查询都要全表扫 accounts（690 行）×（账本 800 单）× 4 个 SUM ≈ 220 万行/次。
        //   月度结算点四五次就把 D1 免费额度（500 万行/天）打光，之后所有带 WHERE 的写入都被
        //   7500 拒绝 → 控制台改了什么都不生效（11-05 晚用户报障的根因）。
        //   ON a.pool=l.pool AND a.uid=l.uid 正好走主键，行数 ≈ 账本行数（实测 1 行/单）。
        d1All('SELECT ' +
          'SUM(CASE WHEN a.uid IS NULL THEN 1 ELSE 0 END) goneCnt, ' +
          'SUM(CASE WHEN l.rb=0 AND l.price IS NOT NULL AND a.uid IS NULL ' +
          'THEN l.price ELSE 0 END) goneMoney, ' +
          'SUM(CASE WHEN l.rb=0 AND l.price IS NOT NULL AND a.uid IS NOT NULL ' +
          'THEN l.price ELSE 0 END) aliveMoney, ' +
          // 2026-11-05：goneValid =「号已删、且本来就是有效单（非补号、非赠号）」的单数。
          // 退单/删号的单不提成 —— 客户的钱退了、服务也没了，再算提成就是给客服发空单的钱。
          // 它同时从 valid 里扣掉，见下面 t.valid。
          'SUM(CASE WHEN l.rb=0 ' +
          "AND NOT (l.name LIKE 'name:%' OR l.name LIKE 'manual:%' OR l.name LIKE '%公益%') " +
          'AND a.uid IS NULL THEN 1 ELSE 0 END) goneValid ' +
          'FROM ledger l LEFT JOIN accounts a ON a.pool=l.pool AND a.uid=l.uid WHERE ' + WL, params),
      ]);
      // 2026-11-05 晚：账本读失败（D1 配额用尽 / 抖动）时不能一声不响地回一张残缺的结算表 ——
      // D1 在额度用尽时是**随机打单个查询**的（这次实测：byPlan 出来了 333 单，byPool 却失败，
      // 于是「成交单数」显示 0，看着像本月没成交）。只要有一路聚合没拿到就直接回 503。
      if (!byPlan || !byAgent || !byPool || !bySrc || !rows || !ghost) {
        return json({ message: '账本读取失败：' + d1ErrHint() + '（不是本月没有成交，是数据库这次没读出来，请稍后重试）' }, 503, CORS);
      }
      const aliveSet = new Set();
      for (const r of (accRows || [])) aliveSet.add(String(r.uid == null ? '' : r.uid));
      const num = (x) => Number(x) || 0;
      const fix = (arr) => (arr || []).map(r => ({
        k: r.plan !== undefined ? r.plan : (r.agent !== undefined ? r.agent : r.pool),
        plan: r.plan, agent: r.agent, pool: r.pool,
        price: r.plan !== undefined ? planPrice(cfgNow, r.plan) : undefined,
        cnt: num(r.cnt), rbCnt: num(r.rbCnt), giftCnt: num(r.giftCnt),
        money: Math.round(num(r.money) * 100) / 100, unpriced: num(r.unpriced),
      }));
      const t = { cnt: 0, rbCnt: 0, giftCnt: 0, money: 0, unpriced: 0 };
      for (const r of (byPool || [])) {
        t.cnt += num(r.cnt); t.rbCnt += num(r.rbCnt); t.giftCnt += num(r.giftCnt);
        t.money += num(r.money); t.unpriced += num(r.unpriced);
      }
      t.money = Math.round(t.money * 100) / 100;
      // 有效单（算提成）在下面拿到 g.goneValid 之后再算 —— 退单/删号的单要扣掉。
      const isGift = (nm) => /^name:|^manual:/.test(String(nm || '')) || String(nm || '').indexOf('公益') >= 0;
      // 2026-11-05：拆「实收」与「号在池」两个金额口径（金额由上面的 ghost 查询算出，不受明细截断影响）。
      //   实收（t.money）= 全部已定价有效单，钱已经收到了，删号不等于没收到；
      //   号在池（t.aliveMoney）= 只算号还在池里的单，这个数才跟控制台筛选出来的单量对得上；
      //   t.goneMoney = 两者之差，即「号已删」那几单的钱，单独列出来不用再手工对。
      let gone = 0;
      const outRows = (rows || []).map(r => {
        const al = aliveSet.has(String(r.uid == null ? '' : r.uid));
        if (!al) gone++;
        return {
          id: r.id, pool: r.pool, uid: String(r.uid || ''), name: String(r.name || ''),
          agent: String(r.agent || ''), plan: String(r.plan || ''),
          price: (r.price === null || r.price === undefined) ? null : Number(r.price),
          day: String(r.day || ''), start: String(r.start || ''), exp: String(r.exp || ''),
          rb: num(r.rb), rbFrom: num(r.rb_from), remark: String(r.remark || ''), src: String(r.src || ''),
          gift: isGift(r.name) ? 1 : 0, alive: al ? 1 : 0,
        };
      });
      const g = (ghost && ghost[0]) || {};
      t.gone = num(g.goneCnt);        // 号已被删的单数：跟控制台筛选出的单量差多少，就是它
      t.goneMoney = Math.round(num(g.goneMoney) * 100) / 100;
      t.aliveMoney = Math.round(num(g.aliveMoney) * 100) / 100;
      t.goneValid = num(g.goneValid);
      // 2026-11-05：有效单（算提成）= 总单 − 补号单 − 赠号/手动号 − 退单（号已删的那部分）。
      // 退单/删号的单不提成：客户钱退了、服务也没了，再算提成等于给客服发空单的钱。
      // 只扣「本来就是有效单」的那批（补号/赠号本来就没算过，不重复扣）。
      t.valid = Math.max(0, t.cnt - t.rbCnt - t.giftCnt - t.goneValid);
      /* 2026-11-10：按登记类型汇总，回答「这个月开了多少新单 / 收了多少续费 / 免费补了多少号」。
         src 取值：new=新登记 / renew=续费 / fix=补号（rb=1）。
         历史数据 src 全是 'reg'（旧代码只写这一个值，分不出新/续），一律归到「新登记」，
         所以切换当月看到的「新登记」会偏多 —— 这是历史数据口径，不是算错。 */
      const _srcBucket = () => ({ cnt: 0, rbCnt: 0, giftCnt: 0, money: 0, unpriced: 0 });
      const srcAgg = { new: _srcBucket(), renew: _srcBucket(), fix: _srcBucket(), other: _srcBucket() };
      for (const r of (bySrc || [])) {
        const raw = String(r.src || '');
        const k = (raw === 'renew') ? 'renew' : (raw === 'fix' ? 'fix' : (raw === 'new' || raw === 'reg' || raw === '') ? 'new' : 'other');
        srcAgg[k].cnt += num(r.cnt);
        srcAgg[k].rbCnt += num(r.rbCnt);
        srcAgg[k].giftCnt += num(r.giftCnt);
        srcAgg[k].money += num(r.money);
        srcAgg[k].unpriced += num(r.unpriced);
      }
      for (const k of Object.keys(srcAgg)) srcAgg[k].money = Math.round(srcAgg[k].money * 100) / 100;
      return json({
        ok: true, month: month, pool: poolF, agent: agentRaw, total: t,
        byPlan: fix(byPlan), byAgent: fix(byAgent), byPool: fix(byPool), bySrc: srcAgg,
        agents: (byAgentAll || []).map(x => ({ agent: String(x.agent == null ? '' : x.agent), cnt: num(x.cnt) })),
        plans: (cfgNow.plans || []),
        rows: outRows,
      }, 200, CORS);
    }
    // 给「待补价」的单子按当前配置价补齐（历史回填时套餐未知的那批）。
    // 只补 price 为 NULL 的行，已经有价的一律不动 —— 防止把过去按老价成交的单改成新价。
    if (url.pathname === '/api/console/ledger_reprice' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      if (!(await consoleAuthFull(body))) return json({ message: '只读口令不能改账' }, 403, CORS);
      if (!d1ok()) return json({ message: 'D1 不可用' }, 503, CORS);
      const month = String(body.month || '').slice(0, 7);
      if (!/^\d{4}-\d{2}$/.test(month)) return json({ message: '请选择月份（YYYY-MM）' }, 400, CORS);
      const cfgNow = await regCfg();
      const where = ['day>=?', 'day<=?', 'price IS NULL', "plan<>''"];
      const params = [month + '-01', month + '-31'];
      const W = where.join(' AND ');
      const plans = await d1All('SELECT plan, COUNT(*) n FROM ledger WHERE ' + W + ' GROUP BY plan', params);
      let fixed = 0, left = [];
      for (const p of (plans || [])) {
        const pr = planPrice(cfgNow, p.plan);
        if (pr < 0) { left.push(p.plan + '(' + p.n + ')'); continue; }
        const ok = await d1Run('UPDATE ledger SET price=? WHERE ' + W + ' AND plan=?',
                               [pr, month + '-01', month + '-31', String(p.plan)]);
        if (ok) fixed += Number(p.n) || 0;
      }
      return json({ ok: true, fixed: fixed,
        message: '已按当前配置价补齐 ' + fixed + ' 单'
          + (left.length ? '；这些档位配置里也没定价，补不了：' + left.join('、') : '') }, 200, CORS);
    }
    // 补号时找原单：按手机号 / 网易 UID / 备注片段搜成交台账。
    // 原号早被删了也能搜到 —— 这正是流水表的意义（accounts 里早没这行了）。
    if (url.pathname === '/api/console/findorder' && request.method === 'POST') {
      const CORS = { 'Access-Control-Allow-Origin': '*' };
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400, CORS); }
      if (!(await consoleAuthFull(body))) return json({ message: '只读口令不能查订单' }, 403, CORS);
      if (!d1ok()) return json({ message: 'D1 不可用' }, 503, CORS);
      const q = String(body.q || '').trim().slice(0, 40);
      if (q.length < 4) return json({ message: '至少输入 4 位（手机号 / UID / 备注片段）' }, 400, CORS);
      const like = '%' + q + '%';
      const rows = await d1All('SELECT id,pool,uid,name,agent,plan,price,day,start,exp,rb,rb_from,remark ' +
        'FROM ledger WHERE name LIKE ? OR uid LIKE ? OR remark LIKE ? ORDER BY day DESC, id DESC LIMIT 20',
        [like, like, like]);
      // 2026-11-06：读失败（rows=null）以前会被下面 `(rows || [])` 变成空列表，
      // 界面显示「没找到原单」—— 假阴性会让补号时误判「这个号没有历史单」，直接算错时长。
      if (!rows) return json({ message: '账本查询失败：' + d1ErrHint() + '（不是没有原单，是这次没读出来）' }, 503, CORS);
      // 顺手标出「这个号现在还在不在池里」，避免把在用的号误当原单
      const uids = [...new Set((rows || []).map(r => String(r.uid || '')).filter(Boolean))];
      const alive = {};
      if (uids.length) {
        const ph = uids.map(() => '?').join(',');
        const a = await d1All('SELECT pool,uid FROM accounts WHERE uid IN (' + ph + ')', uids);
        // 2026-11-06：读失败时 a=null，若继续执行会把所有单都标成「号已删」，
        // 补号时据此判断就会误判（以为原号没了）。直接报错。
        if (!a) return json({ message: '查询号池失败：' + d1ErrHint() + '（不是号已删，是这次没读出来）' }, 503, CORS);
        for (const x of a) alive[String(x.pool) + '|' + String(x.uid)] = 1;
      }
      return json({ ok: true, rows: (rows || []).map(r => ({
        id: r.id, pool: r.pool, uid: String(r.uid || ''), name: String(r.name || ''),
        agent: String(r.agent || ''), plan: String(r.plan || ''),
        price: (r.price === null || r.price === undefined) ? null : Number(r.price),
        day: String(r.day || ''), start: String(r.start || ''), exp: String(r.exp || ''),
        rb: Number(r.rb) || 0, rbFrom: Number(r.rb_from) || 0, remark: String(r.remark || ''),
        alive: !!alive[String(r.pool) + '|' + String(r.uid)],
      })) }, 200, CORS);
    }
    return json({ message: 'not found' }, 404);
}

function json(o, status = 200, extraHeaders) { return new Response(JSON.stringify(o), { status, headers: Object.assign({ 'Content-Type': 'application/json' }, extraHeaders || {}) }); }

// ---- 控制台登录校验（2026-10-22）：用户名固定 xx1031；密码只认 KV 键 CONSOLE_PASS ----
// 2026-10-22 安全修正：原先未配置 CONSOLE_PASS 时回落到缺省口令 xx1031，等于控制台对外敞开
//（实测匿名可登录、可看全池姓名/uid/邮箱、可删任意账号）。现在未配置 = 不开放，必须显式设置。
// 2026-10-27 新增只读口令：KV 键 CONSOLE_RO_PASS。拿它进来只能看，任何写接口一律 403。
//   返回 'full'（满权限）/ 'ro'（只读）/ null（口令不对）。未配置 = 该档位不存在，
//   所以「没配 CONSOLE_RO_PASS」时只读口令天然用不了，不会退化成谁都能只读。
async function consoleRole(body) {
  const u = String((body && body.user) || ''), p = String((body && body.pass) || '');
  if (u !== 'xx1031' || !p) return null;
  let full = '', ro = '', adm = '';
  try { full = cleanKV(await POOL.get('CONSOLE_PASS')); } catch (e) {}
  try { ro = cleanKV(await POOL.get('CONSOLE_RO_PASS')); } catch (e) {}
  // 2026-11-11：手机版号池页内嵌控制台，客服只输一把「号池权限码」（ADMIN_PASS），
  // 所以控制台登录也认它（同为管理级口令，进来就是满权限）。
  try { adm = cleanKV(await POOL.get('ADMIN_PASS')); } catch (e) {}
  // 满权限口令优先判：万一两把口令被设成同一个值，登进来的应该是满权限那档
  if (full && p === full) return 'full';
  if (adm && p === adm) return 'full';
  if (ro && p === ro) return 'ro';
  return null;
}
async function consoleAuth(body) {
  return !!(await consoleRole(body));
}
// 写接口专用：只认满权限口令
async function consoleAuthFull(body) {
  return (await consoleRole(body)) === 'full';
}
// ---- 2026-10-23：两仓库最近一次 run.yml 作业状态（供控制台「运行状态」横条）----
// 以前「今晚 38/38 到底成没成」只能人工去 GitHub 翻，job 绿但分片静默失败也看不出来。
// 拉概览 + job 明细数成功数；结果写 KV 缓存 5 分钟（GitHub token 限 5000 次/小时，
// 控制台刷新一次 = 双仓库×2 请求，不缓存几分钟就能烧掉小半额度）。
// dz 仓库名与 PEER_DEFAULT 同理属于「运行所需常量」写死；GH_TOKEN 未配置时返回空数组，页面显示「未配置」。
async function fetchActionsStatus() {
  const c = await cfg();
  if (!c.ghToken) return [];
  try {
    /* 2026-11-10：搬到 Cache API。原来走 KV，跑批时 TTL 只有 60 秒 ——
       控制台开着就是每分钟写一次，一天 1400+ 次，直接把 KV 免费写额度（1000/天）烧穿。
       这是「KV 写 100%」的头号来源，必须搬走。 */
    const hit = await caGet('actions:cache');
    if (hit) { const arr = JSON.parse(hit); if (Array.isArray(arr)) return arr; }
  } catch (e) { /* 缓存读失败按没有处理 */ }
  const repos = [
    { pool: 'hz', owner: c.owner, repo: c.repo },
    { pool: 'dz', owner: 'xm921017', repo: 'dingzhi' },
  ];
  const out = await Promise.all(repos.map(async (r) => {
    try {
      const base = 'https://api.github.com/repos/' + r.owner + '/' + r.repo;
      const H = { Authorization: 'Bearer ' + c.ghToken, Accept: 'application/vnd.github+json',
                  'User-Agent': 'cron-relay-worker' };
      const T = (p) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 6000))]);
      // 2026-11-04：原来只查 status=completed 的最近一轮 —— 正在跑的那轮（queued/in_progress）
      // 永远不会出现在这里，横条于是一直挂着上一轮的「成功 94/94」，看起来像今天已经跑完了。
      // 现在取最近 5 轮，优先挑没跑完的那轮；全部结束才回落到最近一次已完成。
      const rr = await T(fetch(base + '/actions/workflows/run.yml/runs?per_page=5', { headers: H }));
      if (!rr.ok) throw new Error('runs http ' + rr.status);
      const rd = await rr.json();
      const _runs = rd.workflow_runs || [];
      const run = _runs.filter(x => x.status !== 'completed')[0] || _runs[0];
      if (!run) return { pool: r.pool, ok: false, note: '无运行记录' };
      let jobsOk = 0, jobsTotal = 0, jobsDone = 0;
      try {
        const jr = await T(fetch(base + '/actions/runs/' + run.id + '/jobs?per_page=100', { headers: H }));
        if (jr.ok) {
          const jd = await jr.json();
          let list = jd.jobs || [];
          // 2026-11-04：原来分母直接取第一页条数（per_page=100，不分页）。号池涨到 595 个号
          // 以后 ns=100，job 总数 101 > 100 → 分母被截成 100、jobsOk 也只数第一页，
          // 会永久显示 100/100 并把真实的失败片盖掉。改成用 total_count 当分母并补齐剩余页
          // （单 matrix 上限 250 片 + plan + 少量其它 job，最多 3 页）。
          const _tc = Number(jd.total_count) || list.length;
          for (let pg = 2; pg <= 3 && list.length < _tc; pg++) {
            try {
              const jr2 = await T(fetch(base + '/actions/runs/' + run.id + '/jobs?per_page=100&page=' + pg, { headers: H }));
              if (!jr2.ok) break;
              const jd2 = await jr2.json();
              const more = jd2.jobs || [];
              if (!more.length) break;
              list = list.concat(more);
            } catch (e) { break; }
          }
          jobsTotal = Math.max(_tc, list.length);
          jobsOk = list.filter(j => j.conclusion === 'success').length;
          jobsDone = list.filter(j => j.status === 'completed').length;
        }
      } catch (e) { /* job 明细拉失败不影响概览展示 */ }
      return { pool: r.pool, ok: true, conclusion: run.conclusion || '', status: run.status || '',
               created: run.created_at || '', run_id: run.id, jobs_ok: jobsOk, jobs_done: jobsDone,
               jobs_total: jobsTotal, url: run.html_url || '' };
    } catch (e) {
      return { pool: r.pool, ok: false, note: String((e && e.message) || e).slice(0, 60) };
    }
  }));
  // 2026-11-04：有 run 在跑时缓存只留 60 秒（进度要看得见在动）；全部结束才用 5 分钟，
  // 避免控制台每刷一次就去打 2 个仓库 x (1 次 runs + 1~3 次 jobs) 的 GitHub 接口。
  // 2026-11-10：落 Cache API（不占 KV 写额度）。跑批时 60 秒刷新依旧保留。
  const _live = out.some(x => x && x.ok && x.status && x.status !== 'completed');
  await caPut('actions:cache', JSON.stringify(out), _live ? 60 : 300);
  return out;
}
// ---- 2026-10-24：Cloudflare Cron 定时触发 snap650（GitHub schedule 靠不住）----
// 背景：snap650 用 GitHub 的 schedule（北京 10:00）上线两天 0 次自动运行；同期 relay 计划 22:23
// 实际 02:25 才跑、coverage 计划 20:00 实际 00:43 才跑 —— GitHub 免费档的 schedule 在高负载时
// 会整体推迟数小时甚至丢弃。650 是「日环比」型数据，晚几小时整天判断都失真，必须准点。
// 方案：CF 原生 cron（几乎准点，见 CF 侧 schedules 配置）→ GitHub workflow_dispatch 触发 snap650；
// GitHub 侧 schedule 保留一份晚 2 小时的兜底。两边跑同一个 workflow，重复采集由快照写入的
// 「同号同天 rpc30 大者胜」自然去重，不会写坏数据。
const SNAP650_REPOS = [
  // 两个仓库分属两个 GitHub 账号，PAT 的 admin 权限不通用（实测 xm921018 的 PAT 对 dingzhi
  // 只有 pull 权限，dispatch 直接 403 "Must have admin rights to Repository"），故分开配钥匙：
  // hz 用既有 GH_TOKEN（xm921018，KV 里早已存在），dz 用 GH_TOKEN_DZ（xm921017，2026-10-24 新增）。
  // 2026-11-03：xm921018 账号被 GitHub 停用（suspended，仓库 404），主群迁到 xm921016/cron-relay。
  { pool: 'hz', owner: 'xm921016', repo: 'cron-relay', tokenKey: 'GH_TOKEN' },
  { pool: 'dz', owner: 'xm921017', repo: 'dingzhi', tokenKey: 'GH_TOKEN_DZ' },
];
async function dispatchSnap650(onlyPool) {
  const c = await cfg();
  const jobs = SNAP650_REPOS.filter(r => !onlyPool || onlyPool === 'all' || r.pool === onlyPool);
  const out = [];
  for (const r of jobs) {
    let tok = c.ghToken;
    if (r.tokenKey !== 'GH_TOKEN') {
      tok = cleanKV(await POOL.get(r.tokenKey).catch(() => null)) || '';
      if (!tok) {
        out.push({ pool: r.pool, status: 0, ok: false,
                   message: 'KV 缺少 ' + r.tokenKey + '（该仓库属于另一个 GitHub 账号，需要单独配 PAT）' });
        continue;
      }
    }
    if (!tok) {
      out.push({ pool: r.pool, status: 0, ok: false, message: 'KV 里没有 ' + r.tokenKey });
      continue;
    }
    try {
      const resp = await fetch('https://api.github.com/repos/' + r.owner + '/' + r.repo +
        '/actions/workflows/snapshot.yml/dispatches', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + tok, Accept: 'application/vnd.github+json',
                   'User-Agent': 'cron-relay-worker', 'Content-Type': 'application/json' },
        body: JSON.stringify({ ref: 'main' }),
      });
      // workflow_dispatch 成功返回 204 且 body 为空
      out.push({ pool: r.pool, status: resp.status, ok: resp.status === 204,
                 message: resp.ok ? '' : (await resp.text()).slice(0, 120) });
    } catch (e) {
      out.push({ pool: r.pool, status: 0, ok: false, message: String((e && e.message) || e).slice(0, 120) });
    }
  }
  // 只留最后一次触发记录（1 周过期），控制台/排障时可直接查它到底有没有被调起来
  try {
    await POOL.put('cron:snap650:last', JSON.stringify({ at: new Date().toISOString(), out }),
                   { expirationTtl: 604800 });
  } catch (e) { /* 记录失败不影响触发本身 */ }
  return { ok: out.every(x => x.ok), jobs: out };
}
// ---- 2026-11-05：CF cron 兜底发令「每日 D1 备份」----
// 常规入口是 hz relay 结束后的 workflow_run（天然取删号后的终态）。但那条边偶尔不触发，
// 而 GitHub 自己的 schedule 兜底实测会拖 3~7 小时（名义北京 19:40 → 次日 02:51 才跑）。
// 这里用 CF cron 在下午定点补一枪，只负责发令（导出 600KB / 6000 行 D1 + openssl 加密
// 远超声明的 CPU 预算，Worker 干不了）。
// 三个前提缺一不可，任一不满足就只是「本轮跳过」，等下一个时刻再试：
//   1) hz relay 最近一轮必须是「今天（北京）」且已 completed —— 否则导的是半程态（部分号
//      没播、删号没做完），而且它会占住仓库侧的幂等闸门，把 relay 结束后那次真正的终态
//      备份挡掉，比不备份更糟。
//   2) 没有 d1-daily 正在跑/排队 —— 那情况让它自己跑完，重复发令只是多一次空转。
//   3) 私库 vault 里没有「北京今天」的 d1-YYYY-MM-DD.json.gz.enc —— 有就当天到此为止。
// 三个 cron 时刻天然是重试：16:30 relay 还没收工 → 18:30 / 20:30 再试。
const BACKUP_CRONS = ['30 8 * * *', '30 10 * * *', '30 12 * * *'];   // 北京 16:30 / 18:30 / 20:30
// 2026-11-06：邮件队列的 CF 发令腿。GitHub Actions 的 schedule 实测会整班漏触发（12:00/12:30 两班没跑），
// 所以照 d1-daily 的老套路让 Cloudflare cron 兜底叫班：每小时第 5/35 分（UTC）= 北京 :05/:35，
// 与 GitHub schedule 的 :00/:30 错开，避免两班并发领取（领取虽幂等，但错开更稳）。
// 注意：CF schedules Free 版全账号上限 5 条（实测 10072 报错）且不支持逗号列表，
// 现在只剩每小时第 5 分一条发令腿（另外 4 条是主 cron + 备份发令），派发脚本一班内循环清队列。
const MAIL_CRONS = ['5 * * * *'];
const MAIL_REPO = { owner: 'xm921016', repo: 'cron-relay', workflow: 'notify-mail.yml' };
const BACKUP_REPOS = [
  { pool: 'hz', owner: 'xm921016', repo: 'cron-relay', tokenKey: 'GH_TOKEN' },
  { pool: 'dz', owner: 'xm921017', repo: 'dingzhi', tokenKey: 'GH_TOKEN_DZ' },
];
// 北京日期：备份文件名由 d1_backup.py 用 utcnow()+8h 生成，这里必须同一口径
function bjDate(offsetDays) {
  const t = Date.now() + 8 * 3600 * 1000 + (offsetDays || 0) * 86400000;
  return new Date(t).toISOString().slice(0, 10);
}
function bjDayOf(iso) {
  const ms = Date.parse(iso);
  if (!ms) return '';
  return new Date(ms + 8 * 3600 * 1000).toISOString().slice(0, 10);
}
async function ghJson(tok, url) {
  const H = { Authorization: 'Bearer ' + tok, Accept: 'application/vnd.github+json',
              'User-Agent': 'cron-relay-worker' };
  const r = await Promise.race([
    fetch(url, { headers: H }),
    new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 8000)),
  ]);
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return await r.json();
}
// 2026-11-06：邮件队列发令（CF cron 兜底腿，见 MAIL_CRON 注释）。
// 叫班条件（满足其一）：① 队列里有待发邮件 ② 今天还没做到期扫描（MAIL_SCAN_DAY ≠ 北京今天）。
// 防重叠：上一班（GitHub schedule 或上一条 CF 腿）还在跑/排队就不叠加 —— 领取本身幂等，
// 这里只是省 Actions 空转。发令结果存 KV cron:mail:last（1 周过期）供排障。
async function dispatchMailQueue() {
  // 进门心跳：先落一条 boot 记录再干活 —— 排障用（区分「cron 没触发」和「触发后中途挂」）
  // 2026-11-10：心跳搬到 Cache API（每小时 1 次 × 24 轮 = 24 次/天 KV 写，纯排障用不值这个价）。
  //   末尾的 save() 仍写 KV cron:mail:last，它带 at 时间戳，照样能看出最近一轮有没有跑。
  try { await caPut('cron:mail:boot', JSON.stringify({ at: new Date().toISOString() }), 3600); } catch (e) { }
  const c = await cfg();
  const rec = { at: new Date().toISOString(), day: bjDate(0), action: '', reason: '', pend: 0 };
  const save = async () => {
    try { await POOL.put('cron:mail:last', JSON.stringify(rec), { expirationTtl: 604800 }); } catch (e) { }
  };
  if (!c.ghToken) { rec.action = 'error'; rec.reason = 'KV 缺 GH_TOKEN'; await save(); return rec; }
  try {
    const pendRows = await d1All("SELECT COUNT(*) n FROM mail_queue WHERE state='pending'", []);
    rec.pend = (pendRows && pendRows[0] && Number(pendRows[0].n)) || 0;
    if (pendRows === null) { rec.action = 'error'; rec.reason = '读队列失败（' + (_d1LastErr || 'D1 异常') + '）'; await save(); return rec; }
    let scanDay = null;
    try { scanDay = await POOL.get('MAIL_SCAN_DAY'); } catch (e) { }
    if (rec.pend <= 0 && scanDay === rec.day) {
      rec.action = 'skip'; rec.reason = '队列空且今天已扫到期'; await save(); return rec;
    }
    try {
      const st = await ghJson(c.ghToken, 'https://api.github.com/repos/' + MAIL_REPO.owner + '/' + MAIL_REPO.repo +
        '/actions/workflows/' + MAIL_REPO.workflow + '/runs?per_page=1');
      const latest = ((st && st.workflow_runs) || [])[0];
      if (latest && latest.status !== 'completed') {
        rec.action = 'skip'; rec.reason = '上一班还在' + (latest.status === 'queued' ? '排队' : '运行');
        await save(); return rec;
      }
    } catch (e) { /* 查不了运行状态就照发：领取幂等，不发重 */ }
    const resp = await fetch('https://api.github.com/repos/' + MAIL_REPO.owner + '/' + MAIL_REPO.repo +
      '/actions/workflows/' + MAIL_REPO.workflow + '/dispatches', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + c.ghToken, Accept: 'application/vnd.github+json',
                 'User-Agent': 'cron-relay-worker', 'Content-Type': 'application/json' },
      body: JSON.stringify({ ref: 'main' }),
    });
    rec.action = resp.status === 204 ? 'dispatched' : 'failed';
    rec.reason = resp.status === 204 ? '' : 'HTTP ' + resp.status + ' ' + (await resp.text()).slice(0, 100);
  } catch (e) {
    rec.action = 'error'; rec.reason = String((e && e.message) || e).slice(0, 140);
  }
  await save();
  return rec;
}

async function dispatchDailyBackup(slot) {
  const c = await cfg();
  const rec = { at: new Date().toISOString(), slot: slot, day: bjDate(0), action: '', reason: '', out: [] };
  const save = async () => {
    // 只留最后一次记录（1 周过期），控制台/排障时能看出它到底是被谁挡住 / 有没有发出去
    try { await POOL.put('cron:backup:last', JSON.stringify(rec), { expirationTtl: 604800 }); } catch (e) { }
  };
  const tokOf = async (r) => {
    if (r.tokenKey === 'GH_TOKEN') return c.ghToken || '';
    return cleanKV(await POOL.get(r.tokenKey).catch(() => null)) || '';
  };
  if (!c.ghToken) { rec.action = 'error'; rec.reason = 'KV 缺 GH_TOKEN'; await save(); return rec; }
  try {
    const hz = BACKUP_REPOS[0];
    const hzBase = 'https://api.github.com/repos/' + hz.owner + '/' + hz.repo;
    // 1) relay 今天跑过、且已经结束
    const rel = await ghJson(c.ghToken, hzBase + '/actions/workflows/run.yml/runs?per_page=5');
    const latest = ((rel && rel.workflow_runs) || [])[0];
    if (!latest) { rec.action = 'skip'; rec.reason = 'relay 无运行记录'; await save(); return rec; }
    const relDay = bjDayOf(latest.created_at);
    if (relDay !== rec.day) {
      rec.action = 'skip'; rec.reason = 'relay 今天还没起跑（最近一轮 ' + relDay + '）';
      await save(); return rec;
    }
    if (latest.status !== 'completed') {
      rec.action = 'skip'; rec.reason = 'relay 仍在跑（' + latest.status + '）';
      await save(); return rec;
    }
    // 2) 备份本身没有在跑/排队
    const dbk = await ghJson(c.ghToken, hzBase + '/actions/workflows/d1-daily.yml/runs?per_page=5');
    const live = ((dbk && dbk.workflow_runs) || []).filter(x => x.status !== 'completed')[0];
    if (live) {
      rec.action = 'skip'; rec.reason = 'd1-daily 已在' + (live.status === 'queued' ? '排队' : '运行') + '中';
      await save(); return rec;
    }
    // 3) 今天已有备份？（任一私库有今天文件即算 —— 缺的库重跑也补不上，只说明那个账号 token 挂了）
    const target = 'd1-' + rec.day + '.json.gz.enc';
    const found = [];
    for (const r of BACKUP_REPOS) {
      const tk = await tokOf(r);
      if (!tk) continue;
      try {
        const d = await ghJson(tk, 'https://api.github.com/repos/' + r.owner + '/vault/contents/backup?ref=main');
        const names = (Array.isArray(d) ? d : []).map(x => x && x.name || '');
        if (names.indexOf(target) >= 0) found.push(r.pool);
      } catch (e) { /* 查不到按「没有」处理：宁可多备一份，不能因为判不了就跳过 */ }
    }
    if (found.length) {
      rec.action = 'skip'; rec.reason = '今天已备份（' + found.join('/') + '）';
      await save(); return rec;
    }
    // 4) 发令：两个仓都发 —— 谁先跑完谁写库，后来的被仓库侧幂等闸门挡在几秒内退出
    for (const r of BACKUP_REPOS) {
      const tk = await tokOf(r);
      if (!tk) { rec.out.push({ pool: r.pool, ok: false, note: 'KV 缺 ' + r.tokenKey }); continue; }
      try {
        const resp = await fetch('https://api.github.com/repos/' + r.owner + '/' + r.repo +
          '/actions/workflows/d1-daily.yml/dispatches', {
          method: 'POST',
          headers: { Authorization: 'Bearer ' + tk, Accept: 'application/vnd.github+json',
                     'User-Agent': 'cron-relay-worker', 'Content-Type': 'application/json' },
          body: JSON.stringify({ ref: 'main', inputs: { force: false, test_alert: false } }),
        });
        // workflow_dispatch 成功返回 204 且 body 为空
        rec.out.push({ pool: r.pool, status: resp.status, ok: resp.status === 204,
                       note: resp.ok ? '' : (await resp.text()).slice(0, 100) });
      } catch (e) {
        rec.out.push({ pool: r.pool, status: 0, ok: false, note: String((e && e.message) || e).slice(0, 100) });
      }
    }
    rec.action = rec.out.some(x => x.ok) ? 'dispatched' : 'failed';
  } catch (e) {
    rec.action = 'error';
    rec.reason = String((e && e.message) || e).slice(0, 140);
  }
  await save();
  return rec;
}
// ---- 读一天的快照：聚合 snap:<date>:<pool>:<分片> 所有键 → { hz: {uid: acc}, dz: {uid: acc} } ----
async function readSnapDay(date) {
  const out = { hz: {}, dz: {} };
  // 2026-10-22：快照改读 D1 snapshots 表。原来是 list 一次 + 每个分片一次 get，
  // 且 list 走 KV 配额；现在一条 SELECT 就拿到当天全部号。
  if (d1ok()) {
    const rows = await d1All('SELECT pool,uid,rate,rpc30,cnt,missions,dur,at FROM snapshots WHERE day=?', [date]);
    if (rows) {
      for (const r of rows) {
        const pool = r.pool === 'dz' ? 'dz' : 'hz';
        let mis = {};
        try { mis = r.missions ? JSON.parse(r.missions) : {}; } catch (e) {}
        // 2026-10-23：acc 增加 at（快照写入时间），供控制台「今进度」单元格显示采集时间，
        // 避免把凌晨边跑边采的旧值当成当前真实进度。KV 回退路径的 acc 没有 at，页面判空不显示。
        const acc = { rate: r.rate == null ? null : Number(r.rate), rpc30: r.rpc30 == null ? null : Number(r.rpc30),
                      cnt: r.cnt == null ? null : Number(r.cnt), mis: mis || {},
                      dur: r.dur == null ? null : Number(r.dur), at: r.at || '' };
        const prev = out[pool][r.uid];
        // 同号同天多次写入时，保留 rpc30 更大（更新）的那份
        if (!prev || ((acc.rpc30 || 0) >= (prev.rpc30 || 0))) out[pool][r.uid] = acc;
      }
      return out;
    }
  }
  // ---- KV 回退路径 ----
  try {
    let cursor;
    do {
      const page = await POOL.list({ prefix: 'snap:' + date + ':', cursor: cursor });
      for (const k of (page.keys || [])) {
        const parts = k.name.split(':');
        const pool = parts[2] === 'dz' ? 'dz' : 'hz';
        let v;
        try { v = JSON.parse(await POOL.get(k.name)); } catch (e) { continue; }
        if (!v || !v.accs) continue;
        for (const [uid, acc] of Object.entries(v.accs)) {
          const prev = out[pool][uid];
          // 同号同天多片写入时，保留 rpc30 更大（更新）的那份
          if (!prev || ((acc.rpc30 || 0) >= (prev.rpc30 || 0))) out[pool][uid] = acc;
        }
      }
      cursor = page.list_complete ? null : page.cursor;
    } while (cursor);
  } catch (e) { /* 列表失败按空快照处理 */ }
  return out;
}
// ---- 北京日期减一天 ----
function dateMinus1(dateStr) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateStr || '');
  if (!m) return dateStr;
  const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
  d.setUTCDate(d.getUTCDate() - 1);
  return d.toISOString().slice(0, 10);
}
// ---- 北京日期减 N 天（N>=1；非法输入原样返回）----
function dateMinusN(dateStr, n) {
  let d = dateStr;
  for (let i = 0; i < (n || 0); i++) d = dateMinus1(d);
  return d;
}
// ---- 连续不涨天数（2026-10-23 控制台新增，纯计算无副作用）----
// 2026-11-06：计算整体下推到 D1（原 calcStreaks 保留在下面备查，逻辑与新 SQL 等价）。
// 为什么改：原来每次首屏把 7 天快照（约 4,071 行）整批拉回 JS 再算，
//   回传的只是一张 {uid: 天数} 的小字典；改成 SQL 后最多回 704 行（每号一条），省 3,300+ 行/次。
// 口径与原实现逐条对齐（6 个日期 hz+dz 全量比对 + 8 组边界用例，全部一致）：
//   ① 同池同号同天多行取 MAX(rate)；pool 归一化为 hz/dz；
//   ② rate、pool 的归一化与原 calcStreaks 一致（rate<0 之类不特殊处理，与原逻辑相同）；
//   ③ LAG 按 day 升序取前一天，缺天直接跳过（不补 0），与原「days 列表」逻辑等价；
//   ④ rn 是倒序序号（1=最新），rn<ndays 排除最早那天（最早一天没有「前一天」可比）；
//   ⑤ ≥2 天才输出，与原 streak>=2 一致。
function snapStreakSQL(){
  return 'WITH s AS ('
    + "SELECT (CASE WHEN pool='dz' THEN 'dz' ELSE 'hz' END) AS pool, uid, day, MAX(rate) AS rate "
    + 'FROM snapshots WHERE day>=? AND day<=? AND rate IS NOT NULL GROUP BY 1,2,3), '
    + 'd AS (SELECT pool, uid, rate, '
    + 'LAG(rate) OVER (PARTITION BY pool,uid ORDER BY day) AS prev, '
    + 'ROW_NUMBER() OVER (PARTITION BY pool,uid ORDER BY day DESC) AS rn, '
    + 'COUNT(*) OVER (PARTITION BY pool,uid) AS ndays FROM s), '
    + 'g AS (SELECT pool, uid, '
    + 'MIN(CASE WHEN rn<ndays AND rate>prev THEN rn END) AS first_up, '
    + 'MAX(ndays) AS ndays FROM d GROUP BY 1,2) '
    + 'SELECT pool, uid, '
    + 'CASE WHEN first_up IS NULL THEN ndays-1 ELSE first_up-1 END AS streak '
    + 'FROM g WHERE ndays>=2';
}

// ---- 歌曲/账号元数据字典（2026-11-06 新增）：KV 缓存 15 分钟 ----
// 这两张表只在 backfillMeta 补数据时才变（一天一两次），但原来每次首屏都要全表扫一遍
// （song_meta 815 行 + acc_meta 795 行）。缓存进 KV 后每 15 分钟才真查一次 D1。
// 失败一律降级为 null（页面只是不打「共创/绑错歌」两个标签），绝不影响其它列。
// 大小实测：815+795 行整包 JSON ≈ 163 KB，远低于 KV 单值 25 MB 上限。
// KV 写次数 ≈ 96 次/天（比 D1 省下的行读值这个价）。
async function metaDicts(){
  try{
    const hit = await caGet('meta:dicts');
    if (hit) {
      const o = JSON.parse(hit);
      if (o && Array.isArray(o.songs) && Array.isArray(o.acc)) return o;
    }
  }catch(e){}
  const [songs, acc] = await Promise.all([
    d1All('SELECT song,n_artists,artists,first_artist,gone FROM song_meta'),
    d1All('SELECT uid,artist_id,artist_name FROM acc_meta'),
  ]);
  if (!songs || !acc) return null;   // 任一失败都降级，不写半份缓存
  const payload = { songs: songs, acc: acc, at: Date.now() };
  // 2026-11-10：缓存从 KV 搬到 Cache API（同 meta:tick）。这份字典是纯展示用（不打标签而已），
  //   丢了只是下次重查一遍 D1，而原本 15 分钟一次写 = 96 次/天 KV 写，是全系统最大单笔浪费。
  try{ await caPut('meta:dicts', JSON.stringify(payload), 900); }catch(e){}
  return payload;
}

// 输入：最近 N 天 snapshots 行（day,pool,uid,rate）。
// 口径：按 (池,号,天) 取最大 rate（650 进度单调增，同一天多份写入取最新进度）；
//       跳过无快照的天（数据断层不冤枉号）；从最新一天往前数连续 rate<=前一天 的天数；
//       只有 >=2 的才收录（1 天不涨日环比列本身可见，避免满屏标记）。
// 输出：{ hz:{uid:n}, dz:{uid:n} }
// ⚠️ 2026-11-06 起控制台已改用 snapStreakSQL()，这个函数保留只为对照/回滚，不要再新增调用点。

function calcStreaks(rows) {
  const byKey = {};
  for (const r of (rows || [])) {
    if (!r || r.rate == null) continue;
    const pool = r.pool === 'dz' ? 'dz' : 'hz';
    const k = pool + '|' + String(r.uid);
    const day = String(r.day);
    const v = Number(r.rate) || 0;
    const m = byKey[k] || (byKey[k] = {});
    if (m[day] == null || v > m[day]) m[day] = v;
  }
  const out = { hz: {}, dz: {} };
  for (const k of Object.keys(byKey)) {
    const days = Object.keys(byKey[k]).sort();
    if (days.length < 2) continue;
    let streak = 0;
    for (let i = days.length - 1; i > 0; i--) {
      if (byKey[k][days[i]] <= byKey[k][days[i - 1]]) streak++;
      else break;
    }
    if (streak >= 2) {
      const pool = k.slice(0, k.indexOf('|'));
      out[pool][k.slice(k.indexOf('|') + 1)] = streak;
    }
  }
  return out;
}

// ---- 账号编辑共用逻辑（2026-10-22 从 /api/admin/entry 抽出，行为与原实现逐行一致）----
// 供 /api/admin/entry（管理密码）与 /api/console/entry（控制台登录）两个路由调用。
async function applyEntryEdit(body) {
  const CORS = { 'Access-Control-Allow-Origin': '*' };
  const master = await mergePool();
  const target = master.find(e =>
    (body.uid != null && String(body.uid) !== '' && e.uid != null && String(e.uid) === String(body.uid)) ||
    (body.name && String(e.name) === String(body.name)));
  if (!target) return json({ message: '没找到该账号（可能已被删除）' }, 404, CORS);
  if (body.action === 'delete') {
    // 2026-10-29：改成「先删 D1，成功才删 KV」。旧顺序先删 KV，D1 删失败只打一行日志 →
    // D1 那行还在，下一次 mergePool 会把它悄悄读回来（控制台已显示「已删除」），
    // 而且通知队列照排，号主会收到「账号信息过期」。现在失败就直接报错返回，不留半删状态。
    if (d1ok()) {
      let ok = false;
      try { ok = (await d1Delete(target)) === true; } catch (e) { ok = false; }
      if (!ok) return json({ message: 'D1 删除失败，账号未删除，请稍后重试' }, 500, CORS);
    }
    await POOL.delete(entryKeyOf(target));
    try {
      const log = new Set(await getDeadLog());
      log.add(entryKeyOf(target));
      await POOL.put('dead_log', JSON.stringify([...log].slice(-500)));
    } catch (e) {}
    const kept = master.filter(e => e !== target);
    await d1LogDead([target], 'manual');
    // 2026-10-26：同时进「通知号主」判定队列（12 小时后判是不是真删，见 /api/dead_pending）。
    // 这里是纯新增的一行写入，不影响任何既有行为；写失败也只是少一封邮件。
    try { await d1QueueNotice(target); } catch (e) { console.error('通知队列写入失败:', e && e.message); }
    // master 缓存不再回写（2026-10-22）：读者全走 D1，entry: 独立键才是权威
    await pushPool(kept);
    try { await refreshPoolSnap(); } catch (e) {}
    return json({ ok: true, message: '已删除账号 ' + (target.name || target.uid) }, 200, CORS);
  }
  if (body.action === 'update') {
    const changes = [];
    if (body.ck != null && String(body.ck).trim() !== '') {
      let mu = String(body.ck).trim();
      const mm = mu.match(/MUSIC_U=([^;\s"']+)/);
      if (mm) mu = mm[1];
      if (!/^[A-Za-z0-9%_-]{20,}$/.test(mu)) return json({ message: 'MUSIC_U 格式不对（应为 32 位左右的长字符串）' }, 400, CORS);
      const v = await validateCookie(mu);
      if (!v.ok) return json({ message: '新 CK 校验未通过：' + v.msg }, 400, CORS);
      target.ck = 'MUSIC_U=' + mu;
      changes.push('CK');
    }
    if (body.link != null && String(body.link).trim() !== '') {
      const song = await resolveSong(String(body.link));
      if (!song.ok) return json({ message: song.msg }, 400, CORS);
      target.song = song.song;
      changes.push('歌曲');
    }
    if (body.email != null && String(body.email).trim() !== '') {
      const em = String(body.email).trim();
      const ebMail = emailBad(em);
      if (ebMail) return json({ message: ebMail }, 400, CORS);
      target.email = em;
      changes.push('邮箱');
    }
    if (body.exp != null && String(body.exp).trim() !== '') {
      const x = String(body.exp).trim();
      if (x === 'forever' || x === '永久') { delete target.exp; changes.push('有效期=永久'); }
      else if (/^\d{4}-\d{2}-\d{2}$/.test(x)) { target.exp = x; changes.push('有效期=' + x); }
      else if (/^\d{1,4}$/.test(x)) { const d = beijingDatePlus(parseInt(x, 10)); target.exp = d; changes.push('有效期=' + x + '天(' + d + '止)'); }
      else return json({ message: '有效期格式不对：填天数(如30)、日期(2026-12-31)或"永久"' }, 400, CORS);
    }
    if (body.noListen !== undefined && body.noListen !== null) {
      target.noListen = !!body.noListen;
      changes.push(body.noListen ? '暂停互听(只收不听)' : '恢复互听');
    }
    // 2026-11-01：公益号开关 —— 只帮别人听歌、自己的歌不需要别人听、也不签到。
    // 只打标记不动 song：歌还留在库里，改回普通号第二天就恢复被听，不用重新登记链接。
    // 真正生效的两处：buildPlanFrom 把它登记的歌剔出互听歌环；make_accounts.py 把它排除出签到/笔记。
    if (body.pub !== undefined && body.pub !== null) {
      target.pub = body.pub ? 1 : 0;
      // 2026-11-11：公益号一律改永久 —— 号主明确说「公益号只负责听别人的，自己的歌不能被听」，
      // 这种号没有「到期」概念，它的终点是 CK 失效（判死/删号），不是到期日。
      // 所以设成公益号时无条件把有效期写成 'forever'：即使这一笔同时填了「有效期」也被覆盖
      // （上面的 exp 分支先执行，这里后执行才有这个效果 —— 顺序别调）。
      // 反向（改回普通号）**不动 exp**：需要限期就在「有效期」栏重新填，避免一个误点
      // 让一个付费号白拿永久。响应里会明确提示当前仍是永久。
      if (target.pub) {
        target.exp = 'forever';
        changes.push('设为公益号(只帮别人听，自己的歌不再分给别人听、也不签到)·有效期自动改永久');
      } else {
        changes.push('恢复普通号(参加互听+签到)'
          + (String(target.exp || '') === 'forever' ? '·注意：有效期仍是永久，要限期请在「有效期」栏重填' : ''));
      }
    }
    // 2026-10-27：客服标签 / 套餐档位（补录、纠错用）。留空=不改，与其它栏口径一致。
    // 注意：改套餐不会自动改有效期（两件事分开），要一起改就把「有效期」也填上。
    if (body.agent != null && String(body.agent).trim() !== '') {
      target.agent = normAgent(body.agent);
      changes.push('客服=' + (target.agent || '未标注'));
    }
    if (body.plan != null && String(body.plan).trim() !== '') {
      const rcE = await regCfg();
      const plE = planOf(rcE, body.plan);
      target.plan = plE ? plE.label : normAgent(body.plan).slice(0, 8);
      changes.push('套餐=' + target.plan);
    }
    // ===== 2026-11-05：备注 + 补号标记 =====
    // 补号 = 客户掉线后免费补的一个新号：不计营收、不给客服提成，到期日继承原单（不重置）。
    // 注意顺序：这段放在「有效期」分支之后，所以下面算出来的继承到期日会覆盖掉手工填的值
    // —— 只有当本次没手工填有效期时才覆盖（见 body.exp 判断）。
    // 「没有要修改的内容」这个兜底判断必须留在这段之后：只改备注也是一次有效修改。
    let rbLog = null;
    if (body.note !== undefined && body.note !== null) {
      target.note = String(body.note).replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 200);
      changes.push(target.note ? '备注=' + target.note : '清空备注');
    }
    if (body.rb !== undefined && body.rb !== null) {
      const on = !!body.rb;
      if (on) {
        const rs = String(body.rbStart || '').trim().slice(0, 10);
        let newExp = '';
        if (/^\d{4}-\d{2}-\d{2}$/.test(rs)) {
          target.rbStart = rs;
          // 只在本单有效期没被手工改过时才自动算 —— 手工填的值优先
          if (body.exp === undefined || body.exp === null || String(body.exp).trim() === '') {
            const rcR = await regCfg();
            const plR = (rcR.plans || []).find(it => it.key === target.plan || it.label === target.plan);
            const dys = plR ? (Number(plR.days) || 0) : 0;
            if (dys > 0) {
              newExp = datePlusFrom(rs, dys);
              if (newExp) { target.exp = newExp; changes.push('到期日继承原单=' + newExp); }
            } else if (plR) {
              newExp = 'forever'; target.exp = 'forever';
              changes.push('到期日继承原单=永久');
            }
          }
        }
        target.rb = 1;
        target.rbFrom = Number(body.rbFrom) || 0;
        changes.push('标记为补号（不计营收、不计提成）');
        rbLog = { on: true, from: target.rbFrom, start: target.rbStart || '', exp: newExp };
      } else {
        target.rb = 0;
        target.rbFrom = 0;
        target.rbStart = '';
        changes.push('取消补号标记（恢复为正常单）');
        rbLog = { on: false };
      }
    }
    if (!changes.length) return json({ message: '没有要修改的内容（各栏留空=不改）' }, 400, CORS);
    await POOL.put(entryKeyOf(target), JSON.stringify(target));
    // 2026-10-22：D1 已是唯一读路径，镜像写失败必须显式告诉调用方 ——
    // 否则界面显示"已修改"，第二天读 D1 又变回旧值，谁都不知道出了事。
    let d1okEdit = false;
    // keepEmpty:false —— 控制台是「明确编辑」，允许把备注清空、把补号标记取消（写空/0 生效）。
    try { d1okEdit = await d1Upsert(target, { keepEmpty: false }); } catch (e) { console.error('D1 修改镜像失败:', e && e.message); }
    // 流水表同步：只改这个号最近一笔（老月份已结过账的记录不动）。
    // 写失败只记日志 —— 账本这一刻没跟上，下次编辑/重新登记会再补上，不该让整次编辑报错。
    if (rbLog) {
      try {
        await ledgerMarkRebind(POOL_NAME, target.uid != null ? String(target.uid) : '',
          target.name, rbLog.on, rbLog.from, rbLog.start, target.note || '', rbLog.exp, target);
      } catch (e) { console.error('流水补号标记同步失败:', e && e.message); }
    } else if (body.note !== undefined && body.note !== null) {
      // 只改备注也要同步流水（结算明细里显示的就是流水那条 remark）
      try {
        await ledgerMarkRebind(POOL_NAME, target.uid != null ? String(target.uid) : '',
          target.name, !!target.rb, Number(target.rbFrom) || 0, '', target.note || '', '');
      } catch (e) { console.error('流水备注同步失败:', e && e.message); }
    }
    // master 缓存不再回写（2026-10-22）：读者全走 D1，entry: 独立键才是权威
    await pushPool(master);
    try { await refreshPoolSnap(true); } catch (e) {}   // 编辑可能改了 CK/暂停标记，灾备快照必须同步
    // 2026-11-05 晚：D1 写了失败就直接报错，不再回「已修改 + 小字警告」。
    // 原因：控制台整张表读的都是 D1，写 D1 失败时页面只会显示旧值，用户的理解就是
    // 「编辑功能坏了」；而且原来的警告是绿色提示、900ms 后自动关窗，基本没人看见。
    // KV 那一份仍然留着（不丢），等 D1 恢复后重新保存一次即可覆盖。
    if (d1ok() && !d1okEdit) {
      return json({ ok: false, d1: false,
        message: '保存失败：改动没能写进数据库（' + d1ErrHint() + '）。'
          + '控制台读的是数据库，所以这次改的「' + changes.join('、') + '」刷新后会变回旧值；'
          + '数据库恢复后请再保存一次。' }, 500, CORS);
    }
    return json({ ok: true, d1: !!d1okEdit,
      message: '已修改 ' + (target.name || target.uid) + '：' + changes.join('、')
        + (d1okEdit ? '' : '（⚠️ D1 未绑定，只写进了 KV）') }, 200, CORS);
  }
  return json({ message: '未知操作' }, 400, CORS);
}

const GATE_HTML = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>请输入访问口令</title><style>body{font-family:-apple-system,system-ui,"PingFang SC",sans-serif;background:#f5f6f8;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}.box{background:#fff;border-radius:14px;padding:28px 24px;width:320px;box-shadow:0 2px 12px rgba(0,0,0,.08);text-align:center}h1{font-size:17px;font-weight:600;color:#3b6d11;margin:0 0 6px}p{font-size:13px;color:#666;margin:0 0 18px;line-height:1.6}input{width:100%;box-sizing:border-box;padding:11px;border:1px solid #ddd;border-radius:8px;font-size:15px;text-align:center;letter-spacing:2px}button{margin-top:12px;width:100%;padding:11px;border:0;border-radius:8px;background:#3b6d11;color:#fff;font-size:15px;cursor:pointer}</style></head><body><form class="box" method="get" action=""><h1>成员接入</h1><p>请输入访问口令后继续</p><input name="k" type="password" placeholder="访问口令" autofocus autocomplete="off"><button type="submit">进入</button></form></body></html>`;
const INDEX_HTML = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>成员接入</title><style>body{font-family:-apple-system,system-ui,"PingFang SC",sans-serif;background:#f5f6f8;margin:0;padding:24px 12px;display:flex;flex-direction:column;align-items:center;gap:16px}.head{text-align:center;margin-bottom:2px}.page-title{font-size:20px;font-weight:600;color:#3b6d11;margin:0}.page-sub{font-size:13px;color:#666;margin:6px 0 0}.wrap{display:flex;flex-wrap:wrap;gap:18px;justify-content:center;width:100%;max-width:1060px}.card{background:#fff;padding:26px 22px;border-radius:14px;width:330px;min-width:0;box-sizing:border-box;box-shadow:0 2px 12px rgba(0,0,0,.08)}h1{font-size:17px;margin:0 0 4px}h1.alt{color:#b06a00}p{font-size:13px;color:#666;margin:0 0 16px;line-height:1.5}label{display:block;font-size:13px;margin:12px 0 4px;color:#333}input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #ddd;border-radius:8px;font-size:14px}.row{display:flex;gap:8px}.row input{flex:1}button{margin-top:14px;width:100%;padding:11px;border:0;border-radius:8px;background:#3b6d11;color:#fff;font-size:15px;cursor:pointer}button.mini{margin-top:0;width:auto;padding:10px 12px;font-size:13px;background:#5a8f1d;white-space:nowrap}button:disabled{opacity:.55;cursor:default}.msg{margin-top:14px;font-size:13px;min-height:18px;line-height:1.5}.ok{color:#3b6d11}.err{color:#a32d2d}.tip{color:#666}details{margin-top:14px;font-size:12px;color:#666;line-height:1.6}summary{cursor:pointer;color:#3b6d11}code{background:#eee;padding:1px 4px;border-radius:4px}.admin-entry{margin:10px 0 0;font-size:12px}.admin-entry a{color:#3b6d11;text-decoration:none;border-bottom:1px dashed #3b6d11;padding-bottom:1px}.abox{background:#fff;padding:22px;border-radius:14px;box-shadow:0 2px 12px rgba(0,0,0,.08);width:100%;max-width:1060px;box-sizing:border-box}.stats{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 14px}.stat{flex:1;min-width:100px;background:#f2f7ea;border-radius:10px;padding:10px 12px;text-align:center}.stat b{display:block;font-size:20px;color:#3b6d11}.stat span{font-size:12px;color:#666}.stat.warn b{color:#b06a00}.stat.warn{background:#fdf3e3}.tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}.tools input{flex:1;min-width:160px;padding:9px 10px;border:1px solid #ddd;border-radius:8px;font-size:14px}.tools button{margin-top:0;width:auto;padding:9px 14px;font-size:13px}button.gray{background:#888}.twrap{overflow-x:auto;border:1px solid #eee;border-radius:10px}table{border-collapse:collapse;width:100%;font-size:13px}th{background:#f5f6f8;text-align:left;padding:9px 10px;white-space:nowrap;color:#444;border-bottom:1px solid #eee}td{padding:8px 10px;border-bottom:1px solid #f2f2f2;white-space:nowrap}tr:hover td{background:#fafdf5}.badge{display:inline-block;font-size:11px;padding:1px 7px;border-radius:8px;margin-right:4px}.b-red{background:#fbe4e4;color:#a32d2d}.b-gray{background:#eee;color:#666}.b-yellow{background:#fdf3e3;color:#b06a00}.num{font-family:ui-monospace,Consolas,monospace;color:#555}</style></head><body><div class="head"><h1 class="page-title">成员接入</h1><p class="page-sub">在下方登记新账号；已经登记过的成员，可在下方补录或修改通知邮箱（页面版本 v20261028a）</p></div><div class="wrap"><div class="card"><h1>成员接入（复制 MUSIC_U）</h1><p>自己从浏览器复制 <code>MUSIC_U</code> 粘贴过来，<b>次日生效</b>。注意：<b>每个账号限登记一首歌</b>，重复登记会被拒绝；<b>号池上限 __POOL_LIMIT__ 人</b>，满员后暂停登记。</p><label>MUSIC_U</label><input id="mu" placeholder="粘贴浏览器里的 MUSIC_U 值"><label>分享链接</label><input id="link2" placeholder="粘贴 APP 内分享的单曲链接"><label>手机号（与网易音乐人绑定的手机号）</label><input id="phone2" inputmode="numeric" maxlength="11" placeholder="18888888888"><label>邮箱（掉线或需要验证时邮件通知）</label><input id="email2" type="text" placeholder="账号有变化时邮件通知你"><button id="btn2">直接登记</button><details><summary>怎么拿到 MUSIC_U？（点开看）</summary>用电脑浏览器打开 <code>https://music.163.com</code> 并登录 → 按 <code>F12</code> → 切到「Application / 应用」标签 → 左侧展开 <code>Cookies</code> → 选 <code>music.163.com</code> → 在右边找到名为 <code>MUSIC_U</code> 的那一行，复制它的「Value / 值」整串粘进来即可。</details><div class="msg tip" id="msg2"></div></div><div class="card"><h1 class="alt">绑定 / 更换通知邮箱</h1><p>之前登记时没填邮箱、或者想换一个邮箱，在这里改一下就行。<b>只改邮箱，其他设置原样不动</b>，之后想再换随时能来改。账号有变化时（比如需要完成一次验证、登录过期），会发邮件到这个邮箱提醒你。</p><label>手机号（用手机号登记过的填这个）</label><input id="pm_phone" inputmode="numeric" maxlength="11" placeholder="登记时用的 11 位手机号"><label>MUSIC_U（复制 MUSIC_U 登记的填这个，与手机号二选一即可）</label><input id="pm_mu" placeholder="登记时粘贴的 MUSIC_U"><label>常用邮箱</label><input id="pm_email" type="text" placeholder="name@qq.com"><button id="btn3">保存邮箱</button><div class="msg tip" id="msg3">手机号和 MUSIC_U 填其中一个就行。</div></div></div><script>const $=id=>document.getElementById(id);function normPhone(s){return (s||'').replace(/[０-９]/g,c=>String.fromCharCode(c.charCodeAt(0)-65248)).replace(/[^0-9]/g,'');}function setMsg(el,t,cls){const m=$(el);m.textContent=t;m.className='msg'+(cls?(' '+cls):'');}$('btn2').onclick=async()=>{const musicU=$('mu').value.trim(),link=$('link2').value.trim(),email=$('email2').value.trim(),phone2=normPhone($('phone2').value);if(!musicU){setMsg('msg2','请填写 MUSIC_U','err');return;}if(!/^1\\d{10}$/.test(phone2)){setMsg('msg2','请填写 11 位手机号（登录网易云用的那个，掉了号要靠它认回来）','err');return;}if(!email){setMsg('msg2','请填写邮箱（用于接收任务验证码与异常提醒）','err');return;}if(!link){setMsg('msg2','请填写歌曲链接','err');return;}setMsg('msg2','处理中…');$('btn2').disabled=true;try{const r=await fetch('/api/join_manual',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({musicU,link,email,phone:phone2})});const d=await r.json();if(r.ok){setMsg('msg2',d.message||'登记成功，次日开始。','ok');}else{setMsg('msg2',d.message||'失败','err');}}catch(e){setMsg('msg2','网络错误','err');}$('btn2').disabled=false;};$('btn3').onclick=async()=>{const phone=normPhone($('pm_phone').value),mu=$('pm_mu').value.trim(),email=$('pm_email').value.trim();if(!phone&&!mu){setMsg('msg3','手机号和 MUSIC_U 至少填一个','err');return;}if(!email){setMsg('msg3','请填写常用邮箱','err');return;}setMsg('msg3','正在保存…');$('btn3').disabled=true;try{const r=await fetch('/api/updatemail',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone,mu,email})});const d=await r.json();if(r.ok){setMsg('msg3',d.message||'已保存','ok');}else{setMsg('msg3',d.message||'保存失败','err');}}catch(e){setMsg('msg3','网络错误','err');}$('btn3').disabled=false;};</script></body></html>`;
// 二群已拆分为独立系统（dingzhi worker / dingzhi 仓库 / POOL-DZ 独立 KV 号池），
// 主 worker 只服务一群；原 /g2 路由与二群页面已下线（2026-10-18）。

const ADMIN_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>号池管理后台</title>
<style>
body{font-family:-apple-system,system-ui,"PingFang SC",sans-serif;background:#f5f6f8;margin:0;padding:24px 12px;display:flex;flex-direction:column;align-items:center;gap:16px}
.head{text-align:center}.page-title{font-size:20px;font-weight:600;color:#3b6d11;margin:0}
.page-sub{font-size:13px;color:#666;margin:6px 0 0}
.abox{background:#fff;padding:22px;border-radius:14px;box-shadow:0 2px 12px rgba(0,0,0,.08);width:100%;max-width:1060px;box-sizing:border-box}
h2{font-size:16px;margin:0 0 4px}
.tip{font-size:12px;color:#999;margin:0 0 14px}
input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #ddd;border-radius:8px;font-size:14px}
button{margin-top:12px;width:100%;padding:11px;border:0;border-radius:8px;background:#3b6d11;color:#fff;font-size:15px;cursor:pointer}
button.gray{background:#999}
button.mini{margin-top:0;width:auto;padding:9px 14px;font-size:13px}
button:disabled{opacity:.55;cursor:default}
.msg{margin-top:12px;font-size:13px;min-height:18px}
.ok{color:#3b6d11}.err{color:#a32d2d}
.stats{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 14px}
.stat{flex:1;min-width:104px;background:#f2f7ea;border-radius:10px;padding:10px 12px;text-align:center}
.stat b{display:block;font-size:20px;color:#3b6d11}
.stat span{font-size:12px;color:#666}
.stat.warn{background:#fdf3e3}.stat.warn b{color:#b06a00}
.tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
.tools input{flex:1;min-width:160px}
.twrap{overflow-x:auto;border:1px solid #eee;border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:13px}
th{background:#f5f6f8;text-align:left;padding:9px 10px;white-space:nowrap;color:#444;border-bottom:1px solid #eee}
td{padding:8px 10px;border-bottom:1px solid #f2f2f2;white-space:nowrap}
tr:hover td{background:#fafdf5}
.badge{display:inline-block;font-size:11px;padding:1px 7px;border-radius:8px;margin-right:4px}
.b-red{background:#fbe4e4;color:#a32d2d}.b-gray{background:#eee;color:#666}.b-yellow{background:#fdf3e3;color:#b06a00}
.num{font-family:ui-monospace,Consolas,monospace;color:#555}
a.song{color:#3b6d11;text-decoration:none;border-bottom:1px dotted #3b6d11}
</style>
</head>
<body>
<div class="head"><h1 class="page-title">互听群号池管理后台</h1><p class="page-sub">仅群主可访问，页面不显示登录凭证</p></div>

<div class="abox" id="loginBox">
  <h2>管理密码</h2>
  <p class="tip">输入后浏览器会本地记住，过期可点"退出登录"清除。</p>
  <input id="pw" type="password" placeholder="管理密码（ADMIN_PASS）">
  <button id="btn">进入后台</button>
  <div class="msg" id="lm"></div>
</div>

<div class="abox" id="mainBox" hidden>
  <div class="stats" id="stats"></div>
  <div class="tools">
    <input id="q" placeholder="搜索：账号 / 邮箱 / UID / 歌曲ID">
    <button class="mini" id="btnCsv">导出 CSV</button>
    <button class="mini" id="btnCopy">复制未绑邮箱名单</button>
    <button class="mini" id="btnRefresh">刷新</button>
    <button class="mini gray" id="btnOut">退出登录</button>
  </div>
  <div class="twrap">
    <table>
      <thead><tr><th>#</th><th>账号</th><th>UID</th><th>绑定歌曲</th><th>入池日期</th><th>通知邮箱</th><th>标记</th></tr></thead>
      <tbody id="tb"></tbody>
    </table>
  </div>
  <p class="tip" style="margin:12px 0 0">改绑歌曲 / 删除账号 / 换 CK 等写操作请在本地跑「号池管理.bat」，本后台只读，防止误操作。</p>
</div>

<script>
var POOL=[],STATS={};
function $(id){return document.getElementById(id);}
function msg(t,ok){var m=$('lm');m.textContent=t;m.className='msg'+(ok?' ok':' err');}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function login(){
  var p=$('pw').value.trim();
  if(!p){msg('请输入管理密码');return;}
  $('btn').disabled=true;
  fetch('/api/pool',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pass:p})})
  .then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});})
  .then(function(o){
    $('btn').disabled=false;
    if(!o.ok){msg(o.d.message||'管理密码错误');return;}
    try{localStorage.setItem('poolAdminPass',p);}catch(e){}
    POOL=o.d.entries||[];STATS=o.d.stats||{};
    $('loginBox').hidden=true;$('mainBox').hidden=false;
    render();
  }).catch(function(){ $('btn').disabled=false; msg('网络错误，请重试'); });
}
$('btn').onclick=login;
$('pw').onkeydown=function(e){if(e.key==='Enter')login();};
$('btnOut').onclick=function(){try{localStorage.removeItem('poolAdminPass');}catch(e){}location.reload();};
$('btnRefresh').onclick=function(){fetchPool();};
$('q').oninput=render;
$('btnCopy').onclick=function(){
  var noMail=POOL.filter(function(e){return !e.email;});
  if(!noMail.length){alert('全部已绑定邮箱');return;}
  var txt='请以下成员到登记页绑定通知邮箱（账号异常时邮件通知本人）：\\n'+noMail.map(function(e){return e.name;}).join('\\n');
  function done(){$('btnCopy').textContent='已复制 '+noMail.length+' 条';setTimeout(function(){$('btnCopy').textContent='复制未绑邮箱名单';},2500);}
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(txt).then(done,function(){fallback();});}else fallback();
  function fallback(){var ta=document.createElement('textarea');ta.value=txt;document.body.appendChild(ta);ta.select();try{document.execCommand('copy');done();}catch(e){alert('复制失败，请手动选择');}document.body.removeChild(ta);}
};
$('btnCsv').onclick=function(){
  var rows=[['序号','账号','UID','歌曲ID','入池日期','邮箱','互听状态']];
  // 2026-10-26 修复：末列原来是 e.marks，但 /api/pool 从不返回该字段 → 这一列永远是空。
  // 改成导出现有字段里真正有意义的「互听状态」。
  POOL.forEach(function(e,i){rows.push([i+1,e.name,e.uid||'',e.song||'',e.added||'',e.email||'',e.noListen?'只收不听':'正常']);});
  var csv='\ufeff'+rows.map(function(r){return r.map(function(v){return '"'+String(v).replace(/"/g,'""')+'"';}).join(',');}).join('\\r\\n');
  var a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
  a.download='号池_'+new Date().toISOString().slice(0,10)+'.csv';
  document.body.appendChild(a);a.click();document.body.removeChild(a);
};
function fetchPool(){
  var p='';try{p=localStorage.getItem('poolAdminPass')||'';}catch(e){}
  if(!p){$('loginBox').hidden=false;$('mainBox').hidden=true;return;}
  fetch('/api/pool',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pass:p})})
  .then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});})
  .then(function(o){
    if(!o.ok){msg(o.d.message||'请重新登录');$('loginBox').hidden=false;$('mainBox').hidden=true;return;}
    POOL=o.d.entries||[];STATS=o.d.stats||{};render();
  }).catch(function(){});
}
function badges(e){
  var h='';
  if(e.noListen)h+='<span class="badge b-red">只收</span>';
  if(!e.song||e.pub)h+='<span class="badge b-gray">公益</span>';
  if(!e.email)h+='<span class="badge b-yellow">无邮箱</span>';
  if(String(e.name).indexOf('qr:')===0)h+='<span class="badge b-gray">扫码</span>';
  return h||'<span style="color:#bbb">正常</span>';
}
function render(){
  var q=($('q').value||'').trim().toLowerCase();
  var list=POOL.filter(function(e){
    if(!q)return true;
    return (e.name+' '+(e.email||'')+' '+(e.uid||'')+' '+(e.song||'')).toLowerCase().indexOf(q)>=0;
  });
  $('stats').innerHTML=
    '<div class="stat"><b>'+STATS.total+'</b><span>号池总数</span></div>'
   +'<div class="stat"><b>'+STATS.withMail+'</b><span>已绑邮箱</span></div>'
   +'<div class="stat'+(STATS.noMail?' warn':'')+'"><b>'+STATS.noMail+'</b><span>未绑邮箱</span></div>'
   +'<div class="stat'+(STATS.noListen?' warn':'')+'"><b>'+STATS.noListen+'</b><span>只收号</span></div>'
   +'<div class="stat"><b>'+STATS.public+'</b><span>公益号</span></div>'
   +'<div class="stat"><b>'+(STATS.limit||1200)+'</b><span>人数上限</span></div>'
   +'<div class="stat'+(STATS.remain<=20?' warn':'')+'"><b>'+STATS.remain+'</b><span>剩余名额</span></div>'
   +'<div class="stat"><b>'+(list.length)+'</b><span>当前筛选</span></div>';
  var h='';
  list.forEach(function(e,i){
    var song=e.song?'<a class="song" target="_blank" href="https://music.163.com/song?id='+e.song+'">'+e.song+'</a>':'<span style="color:#bbb">—</span>';
    h+='<tr><td class="num">'+(i+1)+'</td><td>'+esc(String(e.name||'').replace(/^qr:.+/,'扫码登录').replace(/^manual:/,'手动·'))+'</td><td class="num">'+esc(e.uid)+'</td><td class="num">'+song+'</td><td class="num">'+esc(e.added)+'</td><td>'+esc(e.email||'—')+'</td><td>'+badges(e)+'</td></tr>';
  });
  $('tb').innerHTML=h||'<tr><td colspan="7" style="text-align:center;color:#999;padding:20px">没有匹配的账号</td></tr>';
}
try{
  var _pw=null;
  try{var _h=(location.hash||'').match(/(?:^#|[#&])pw=([^&]*)/)||(location.search||'').match(/[?&]pw=([^&]*)/);if(_h)_pw=decodeURIComponent(_h[1]);}catch(e){}
  if(_pw){try{history.replaceState(null,'',location.pathname);}catch(e1){};var _el=$('pw');if(_el)_el.value=_pw;login();}
  else if(localStorage.getItem('poolAdminPass')) fetchPool();
}catch(e){}
</script>
</body>
</html>`;


// ---- 进阶控制台页面（2026-10-22）：两池账号每日快照 + 日环比 + 编辑。登录账号/密码均 xx1031（CONSOLE_PASS 可覆盖密码）----
const CONSOLE_HTML = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>650任务进阶控制台</title><style>
body{font-family:-apple-system,system-ui,"PingFang SC",sans-serif;background:#f5f6f8;margin:0;padding:20px 12px}
.head{text-align:center;margin-bottom:10px}.page-title{font-size:19px;font-weight:600;color:#3b6d11;margin:0}.page-sub{font-size:12px;color:#888;margin:5px 0 0}
.abox{background:#fff;padding:20px;border-radius:14px;box-shadow:0 2px 12px rgba(0,0,0,.08);width:100%;max-width:1800px;box-sizing:border-box;margin:0 auto 14px}
#loginBox{max-width:520px}
input,select{padding:9px 10px;border:1px solid #ddd;border-radius:8px;font-size:13px;box-sizing:border-box}
button{padding:9px 14px;border:0;border-radius:8px;background:#3b6d11;color:#fff;font-size:13px;cursor:pointer}
button.gray{background:#888}button.warn{background:#a32d2d}button:disabled{opacity:.55;cursor:default}
.msg{font-size:13px;min-height:16px;margin-top:8px}.ok{color:#3b6d11}.err{color:#a32d2d}
/* 2026-11-05 改（用户要求）：统计卡从 flex 换成 grid —— 以前 13 张卡里第 13 张会被挤到第二行
   并被 flex:1 拉成整行宽（「已达100%」那块），非常难看。grid 的 auto-fit 会把空轨道折叠、
   item 平分到各列，行不齐时最后一行也只占一列宽；同时整体尺寸收小一档（min 96→88px，
   数字 19→18px，标签 11→10.5px），13 张卡在 1400px 以上宽度就能排成一行。
   每张卡现在还是「按钮」：点一下按这一项筛表格（见 pickStat），所以加了 cursor/hover/on 态。 */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(84px,1fr));gap:7px;margin:0 0 12px}
.stat{background:#f2f7ea;border:1px solid transparent;border-radius:10px;padding:7px 6px;text-align:center;min-width:0;cursor:pointer}
.stat b{display:block;font-size:18px;line-height:1.2;color:#3b6d11}
.stat span{display:block;font-size:10.5px;line-height:1.3;color:#666;overflow-wrap:break-word}
.stat:hover{background:#e9f3dc;border-color:#d5e5bd}
.stat.warn{background:#fdf3e3}.stat.warn b{color:#b06a00}
.stat.on{background:#3b6d11;border-color:#3b6d11}
/* 卡片 b 上有内联色（红/绿/灰/橙），选中态必须 !important 才盖得住 */
.stat.on b,.stat.on span{color:#fff!important}
.stat.warn.on{background:#b06a00;border-color:#b06a00}
.stat.on:hover{background:#31590e}
/* 2026-10-27 新增：套餐汇总条（按「登记时买的套餐」统计，跟着客服/套餐筛选一起变） */
.plans{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 12px}
.pl{background:#fff;border:1px solid #e8eaee;border-radius:9px;padding:6px 12px;font-size:12px;color:#555}
.pl b{font-size:15px;color:#3b6d11;margin-left:5px}
.pl.muted{color:#9aa5b1}.pl.muted b{color:#aab4c0}
.ro{display:inline-block;background:#fdf3e3;color:#b06a00;border-radius:8px;padding:2px 9px;font-size:11px;margin-left:6px;vertical-align:middle;font-weight:400}
.tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
.tools input{min-width:130px}.tools input#q{flex:1;min-width:160px}
/* 2026-10-27 二次改（用户要求）：不要单独的「入池范围」控件，
   就在原来那个单日期后面再放一个日期，两个框连起来当一个日期范围用。 */
.dr{display:inline-flex;align-items:center;gap:3px;background:#f5f6f8;border:1px solid #e8eaee;border-radius:8px;padding:2px 6px}
.dr em{font-style:normal;color:#aab4c0;font-size:12px}
.dr input{border:1px solid #ddd;border-radius:6px;padding:5px 6px;font-size:12.5px;min-width:118px;background:#fff}
.dr .dn{font-style:normal;font-size:11.5px;color:#3b6d11;font-weight:700;padding:0 2px;display:none}
.dr .dx{cursor:pointer;color:#999;font-size:15px;padding:0 4px;line-height:1;user-select:none;display:none}
.dr .dx:hover{color:#a32d2d}
.dr.on{background:#f2f7ea;border-color:#cfe0b4}
.dr.on .dn,.dr.on .dx{display:inline}
.tab{padding:8px 14px;border-radius:8px;background:#eee;color:#555;cursor:pointer;font-size:13px}
.tab.on{background:#3b6d11;color:#fff}
.twrap{overflow:auto;max-height:calc(100vh - 170px);border:1px solid #eee;border-radius:10px}
table{border-collapse:collapse;width:auto;min-width:100%;max-width:none;font-size:12.5px;white-space:nowrap}
th{background:#f5f6f8;text-align:left;padding:8px 9px;color:#444;border-bottom:1px solid #eee}
.twrap th{position:sticky;top:0;z-index:3;box-shadow:inset 0 -1px 0 #eee,0 1px 4px rgba(0,0,0,.05)}
td{padding:7px 9px;border-bottom:1px solid #f2f2f2}
tr:hover td{background:#fafdf5}
.badge{display:inline-block;font-size:11px;padding:1px 7px;border-radius:8px;margin-right:3px}
.b-hz{background:#e8f2df;color:#3b6d11}.b-dz{background:#e3ecf7;color:#2d5aa3}
/* 2026-11-02 控制台邮箱列：字号小一号；user-select:all 让单击即整段选中，方便复制去发信 */
.mail{font-size:12px;color:#475569;user-select:all}
/* 2026-11-11 音乐人列限宽：约 5 个汉字宽，超长截断成省略号，悬停看全名 —— 防止长昵称/宽字符把表格撑出横向滚动条 */
td[data-l="歌手"] .mus{display:inline-block;max-width:5em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:bottom}
/* 2026-11-11 邮箱/歌曲/音乐人三列收窄：内边距减半（默认 9px → 5px），邮箱超长截断省略号、悬停看全名 —— 压掉列间大空隙，避免横向滚动 */
th.thin,td.mail,td[data-l="歌曲"],td[data-l="歌手"]{padding-left:5px;padding-right:5px}
.mail .eml{display:inline-block;max-width:11em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:bottom}
.b-red{background:#fbe4e4;color:#a32d2d}.b-gray{background:#eee;color:#666}.b-yellow{background:#fdf3e3;color:#b06a00}
.b-orange{background:#fdeee0;color:#b85c00}
/* 2026-10-25 售后标签新增两色：绿=已完成不用管，蓝=刚入池正常等待 */
.b-green{background:#e3f4e3;color:#1e7a1e}.b-blue{background:#e3effa;color:#255ea6}
.snap-at{font-size:10px;color:#aaa;font-weight:400;margin-top:1px;line-height:1.2}
.num{font-family:ui-monospace,Consolas,monospace;color:#555}
a.song{color:#3b6d11;text-decoration:none;border-bottom:1px dotted #3b6d11}
.up{color:#c0392b;font-weight:600}.down{color:#1e8449;font-weight:600}.flat{color:#999}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.35);display:flex;align-items:center;justify-content:center;z-index:9}
.modal[hidden]{display:none}
.mbox{background:#fff;border-radius:14px;padding:22px;width:420px;max-width:94vw;max-height:88vh;overflow:auto}
.mbox h3{margin:0 0 4px;font-size:16px}.mbox label{display:block;font-size:12px;color:#555;margin:10px 0 3px}
.mbox input,.mbox select{width:100%}
.row2{display:flex;gap:8px;margin-top:14px}.row2 button{flex:1}
.mission{font-size:11px;color:#666;max-width:180px;overflow:hidden;text-overflow:ellipsis}
.mtag{display:inline-block;font-size:11px;background:#f1f2f4;color:#666;border-radius:6px;padding:1px 6px;margin-right:3px;white-space:nowrap}
.mtag i{font-style:normal;color:#999}
.lgd{font-size:12px;color:#555;line-height:1.85}
.lgd b{color:#333}
.lgd code{background:#f4f4f6;border-radius:4px;padding:1px 5px;font-size:11px;color:#a33}
.lgd table{white-space:normal;margin:6px 0 2px}
.lgd td,.lgd th{vertical-align:top;padding:5px 8px;font-size:12px}
.lgd .badge{white-space:nowrap}
.runbar{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 12px}
.rb{flex:1;min-width:170px;background:#fff;border:1px solid #e6e6e6;border-radius:10px;padding:8px 12px;font-size:12px;color:#555;line-height:1.5}
.rb b{font-size:12.5px;color:#333}
.rb .good{color:#3b6d11;font-weight:600}.rb .bad{color:#a32d2d;font-weight:600}.rb .muted{color:#999}
.rb a{color:#3b6d11}
.deadbox{margin:10px 0 0;font-size:12px;color:#555}
.deadbox summary{cursor:pointer;color:#3b6d11;padding:4px 0}
.deadbox table{margin-top:6px;border:1px solid #eee;border-radius:8px}
/* 手机端（<=860px）把 17 列表格改成卡片流。纯 CSS、零 JS 改动 —— 判定口径与桌面端完全同一份，
   只是换了个呈现方式；桌面端（>860px）一行都不受影响。列名读 td 的 data-l（见 render），
   这里只排显示顺序，顺序同 thead：
   1# 2池 3账号 4客服 5UID 6歌曲 7歌手 8时长 9昨日650 10今日650 11较昨日 12近30日播放 13笔记任务
   13入池 14有效期 15套餐 16标记 17操作 */
@media (max-width:860px){
  body{padding:10px 8px}
  .head{margin-bottom:8px}.page-title{font-size:16px}.page-sub{font-size:11px;line-height:1.5}
  .abox{padding:12px;border-radius:12px;margin-bottom:10px}
  #loginBox{max-width:100%}
  /* 2026-11-05：统计卡改 grid 后，手机端只换列宽/尺寸（flex 属性对 grid item 无效，已删） */
  .stats{grid-template-columns:repeat(auto-fit,minmax(78px,1fr));gap:5px;margin-bottom:10px}
  .stat{padding:6px 4px;border-radius:9px}
  .stat b{font-size:15px}.stat span{font-size:10px;line-height:1.25}
  .plans{gap:6px;margin-bottom:10px}
  .pl{flex:1 1 40%;padding:5px 9px;font-size:11.5px}
  .pl b{font-size:14px}
  .tools{gap:6px;margin-bottom:8px}
  .tools input,.tools select,.tools button,.mini{padding:8px 10px;font-size:12.5px}
  /* 手机端：两个日期框平分一行，否则各自换行会顶掉半屏 */
  .dr{width:100%;flex:1 1 100%;justify-content:space-between;padding:3px 5px}
  .dr input{flex:1;min-width:0;padding:7px 4px;font-size:12px}
  .dr .dn{flex:0 0 auto}
  .runbar{gap:6px;margin-bottom:10px}
  .rb{min-width:0;flex:1 1 100%;padding:7px 10px;font-size:11.5px}
  .twrap{border:0;border-radius:0;max-height:none!important;height:auto!important;overflow:visible;background:transparent}
  .twrap table,.twrap tbody{display:block}
  .twrap thead{display:none}
  .twrap tr{display:flex;flex-wrap:wrap;align-items:baseline;gap:2px 10px;background:#fff;
    border:1px solid #e8eaee;border-radius:12px;padding:9px 11px;margin:0 0 9px}
  .twrap td{display:flex;flex-wrap:wrap;align-items:baseline;gap:0 5px;border:0;padding:2px 0;
    white-space:normal;flex:1 1 45%;min-width:0;font-size:12.5px;line-height:1.5}
  .twrap td::before{color:#9aa5b1;font-size:11px;flex:0 0 auto}
  .twrap td .snap-at{flex:0 0 100%}
  .twrap td:nth-child(1){order:0;flex:0 0 auto;font-size:11px;color:#b3bcc6;padding-bottom:0}
  .twrap td:nth-child(2){order:1;flex:0 0 auto}
  .twrap td:nth-child(3){order:2;flex:1 1 auto;font-size:14px;font-weight:600;color:#222;padding-bottom:3px}
  .twrap td:nth-child(4){order:3;flex:0 0 auto}
  .twrap td:nth-child(10){order:4;flex:1 1 45%;font-size:14px}
  .twrap td:nth-child(11){order:5;flex:1 1 45%}
  .twrap td:nth-child(17){order:6;flex:0 0 100%;padding:4px 0 2px}
  .twrap td:nth-child(9){order:7;flex:1 1 45%}
  .twrap td:nth-child(12){order:8;flex:1 1 45%}
  .twrap td:nth-child(8){order:9;flex:1 1 45%}
  .twrap td:nth-child(14){order:10;flex:1 1 45%}
  .twrap td:nth-child(15){order:11;flex:1 1 45%}
  .twrap td:nth-child(16){order:12;flex:1 1 45%}
  .twrap td:nth-child(13){order:13;flex:0 0 100%}
  .twrap td:nth-child(5){order:14;flex:1 1 45%}
  .twrap td:nth-child(7){order:15;flex:0 0 100%}
  .twrap td:nth-child(6){order:16;flex:1 1 45%;word-break:break-all}
  .twrap td:nth-child(18){order:20;flex:0 0 100%;padding-top:6px;margin-top:4px;border-top:1px solid #f2f4f6}
  .twrap td:nth-child(18) button{width:100%}
  /* 2026-10-27：列名不再用 nth-child 硬编码，改成读 td 的 data-l 属性。
     原来每加一列都要手工重排 15 条 nth-child，10-26 就因为对不上出过一次排版事故；
     改用 data-l 后只有「显示顺序」还需要 nth-child，标签永远跟着格子走。 */
  .twrap td::before{content:attr(data-l);color:#9aa5b1;font-size:11px;flex:0 0 auto}
  .twrap td:not([data-l])::before{content:none}
  /* 「删号记录」6 列表 / 「标记对照表」3 列表，在 360px 下每列只剩几十 px，会被挤成一字一行。
     手机端改成一条一条的块：删号记录 → 首行 池+UID+账号，下面 原因/通知/时间 各占一行带标签；
     对照表 → 标记一行、意思一行、要怎么处理一行（前缀「意思｜」「处理｜」代替表头）。桌面端不受影响。 */
  #deadList table{display:block;white-space:normal;border:0;font-size:11.5px}
  #deadList thead{display:none}
  #deadList tbody{display:block}
  #deadList tr{display:block;padding:6px 0;border-bottom:1px solid #f2f4f6}
  #deadList td{display:inline-block;padding:0 8px 0 0;border:0;vertical-align:top}
  #deadList td:nth-child(4),#deadList td:nth-child(5),#deadList td:nth-child(6){display:block}
  #deadList td:nth-child(4)::before{content:"原因｜";color:#9aa5b1}
  #deadList td:nth-child(5)::before{content:"通知｜";color:#9aa5b1}
  #deadList td:nth-child(6)::before{content:"时间｜";color:#9aa5b1}
  .lgd{font-size:11.5px}
  .lgd table{display:block;white-space:normal;border:0;margin:4px 0 2px}
  .lgd thead{display:none}
  .lgd tbody,.lgd tr{display:block}
  .lgd tr{padding:6px 0 7px;border-bottom:1px solid #f2f4f6}
  .lgd td{display:block;padding:1px 0;border:0;line-height:1.65}
  .lgd td:nth-child(2)::before{content:"意思｜";color:#9aa5b1;font-size:11px}
  .lgd td:nth-child(3)::before{content:"处理｜";color:#9aa5b1;font-size:11px}
  .lgd td[colspan]{display:block;margin:2px 0 0;padding:4px 8px;border-radius:6px}
}
</style></head><body>
<div class="head"><h1 class="page-title" id="ptitle">650 任务进阶控制台</h1><p class="page-sub">两群账号每日快照 · 数据由 Actions 播放时段顺带采集（T+1 可见）· CK 不在页面展示</p></div>
<div class="abox" id="loginBox">
  <h3 style="margin:0 0 10px">输入控制台口令</h3>
  <p style="margin:0 0 8px;color:#888;font-size:13px;line-height:1.5">账号固定 <b>xx1031</b>，只需填口令。<b>本机不保存口令，每次打开这一页都要重新输入</b>。从「网易云CK助手」或手机 App 点「进阶控制台」进来时，口令由软件带过来，不用在这里再输一遍。</p>
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    <input id="lu" value="xx1031" readonly title="账号固定 xx1031，不用改" style="width:92px;flex:0 0 92px;background:#f5f5f5;color:#999;text-align:center">
    <input id="lp" type="password" placeholder="控制台口令" style="flex:1;min-width:160px">
    <button id="lbtn">进入</button>
  </div>
  <div class="msg" id="lm"></div>
</div>
<div class="abox" id="mainBox" hidden>
  <div class="runbar" id="runbar"></div>
  <div class="stats" id="stats"></div>
  <div class="plans" id="plans"></div>
  <div class="tools">
    <span class="tab on" data-p="all">全部</span><span class="tab" data-p="hz">主群</span><span class="tab" data-p="dz">定制群</span>
    <select id="fagent" title="按客服筛选（顶部套餐汇总、所有统计都跟着变）"><option value="">客服：全部</option></select>
    <select id="fplan" title="按套餐筛选"><option value="">套餐：全部</option></select>
    <span class="dr" id="dr" title="入池日期范围：只看这段时间登记进池的号。只填一端也行（只填左边=这天及以后，只填右边=这天及以前），两边都空=全部。清空点右边的 ×"><input type="date" id="date" title="入池起始日（含）"><em>~</em><input type="date" id="dateTo" title="入池结束日（含）"><i class="dn" id="dn"></i><span class="dx" id="dClear" title="清除入池日期范围">×</span></span>
    <input id="q" placeholder="搜索：账号 / 邮箱 / UID / 歌曲ID / 客服">
    <select id="sort"><option value="default">排序：默认</option><option value="delta">排序：日涨幅↓</option><option value="rate">排序：今日进度↓</option></select>
    <button class="mini" id="btnCsv">导出CSV</button>
    <button class="mini" id="btnRefresh">刷新</button>
    <button class="mini" id="btnLedger" style="display:none" title="按月算钱：谁登记的、买了什么套餐、一共多少钱；补号单单独列出不计提成">月度结算</button>
    <button class="mini gray" id="btnCfg" style="display:none">客服名单</button>
    <button class="mini gray" id="btnDev" style="display:none" title="按客服电脑授权：未授权的机器码不能生成登记链接">设备授权</button>
    <button class="mini gray" id="btnReg" style="display:none" title="生成买家自助登记链接；续费/补登必须选原单，类型定在链接上">登记链接</button>
    <button class="mini gray" id="btnOut">退出</button>
  </div>
  <div class="twrap"><table><thead><tr>
    <th>#</th><th>池</th><th>账号</th><th title="这条登记是谁录的（客服标签，登记前必须在 APK/EXE 里选）">客服</th><th>UID</th><th title="通知邮箱：账号失效 / 需要验证时发到这里。空的（—）= 没登记，通知不到人" class="thin">邮箱</th><th class="thin">绑定歌曲</th><th title="该号自己的音乐人昵称（acc_meta 元数据回填；没同步到显示 —）。限宽约 5 个字，超长截断成 …，鼠标悬停看全名。2026-11-11 起不再显示歌的歌手列表与 ✓/✗（共创人太多把行撑太高），绑错歌判定走标记列" class="thin">音乐人</th><th>时长</th><th id="thA" title="起始日快照里的 650 任务完成度（近30日有效播放，100%=已达标）">昨日<br>650进度</th><th id="thB" title="结束日快照里的 650 任务完成度（近30日有效播放，100%=已达标）">今日<br>650进度</th><th id="thD" title="结束日650进度 - 起始日650进度；红色=涨，绿色=跌，0=这段时间没动，灰色「周期归零」=换新周期导致的 100→0（不是掉量）">较昨日</th><th title="网易工作台 recentPlayCount30：近30日播放次数（不是有效播放，也不等于650进度）">近30日<br>播放量</th><th title="笔记任务（发布图文笔记，按 已发x/4 显示：30天内发布图文笔记天数≥4，4/4=已完成）；跟播放/650 无关，不看也不影响">笔记<br>任务</th><th>入池</th><th>有效期</th><th title="登记时买的套餐（1月/半年/1年/2年/永久）。顶部「套餐汇总」按这一列统计，不按剩余天数算">套餐</th><th title="内部备注（号主看不到）。补号会在这里标一个「补」：客户掉线后免费补的新号，不计营收、不计客服提成">备注</th><th>标记</th><th>操作</th>
  </tr></thead><tbody id="tb"></tbody></table></div>
  <details class="deadbox" id="deadBox" hidden><summary>删号记录 / 待复核账号（最近 12 条，来自 D1 dead_log 与 accounts.suspect_at）</summary>
  <div class="muted" style="margin:6px 0 8px">原因：<b>手动删除</b>＝你在控制台/号池工具点的删除；<b>Cookie失效</b>＝播放前验活自动判死；<b>到期清理</b>＝账号有效期到了自动移除。已回池（迁移到另一群或当天重登）的号不算删号。<br>通知：<b>已通知</b>＝确认发出；<b>已回池·不发</b>＝号还在跑；<b>无邮箱·不发</b>＝没登记邮箱；<b>待判·12h</b>＝删后满 12 小时才判定该不该发；<b>自动判死·run.py 发信</b>＝早期记录，发信由播放任务临时触发，发没发事后查不到。</div><div id="deadList"></div></details>
  <details class="deadbox" id="legendBox"><summary><b>标记看不懂 / 数字怎么读？点开这份对照表</b></summary><div class="lgd">
    <b>一、先认清三个数（别再混）：</b>「650进度」= 音乐人后台的 650 任务完成度，100% 才算做完，是唯一有意义的成绩；「近30日播放量」= 工作台统计的播放次数，刷再多也不直接等于进度；「笔记任务」= 网易塞在同一组里的另一个小任务（发布图文笔记），跟播放和 650 一点关系都没有，一列显示「—」也是正常的。
    <br><b>二、标记对照（按「问题出在哪」分组，越靠上的越该先处理）：</b>
    <table><thead><tr><th>标记</th><th>意思</th><th>要怎么处理</th></tr></thead><tbody>
    <tr><td colspan="3" style="background:#fdf0f0;font-weight:600;color:#a32d2d">A · 歌曲问题 —— 必须改歌，刷多少都不会涨</td></tr>
    <tr><td><span class="badge b-red">歌曲无效·绑错歌</span></td><td>他登记的这首歌，作者里<b>没有他自己的音乐人身份</b>（相当于绑了别人的歌）。两种情况都算：多人合唱里没他；<b>独唱但作者是别人</b>（10-25 补，只在近30日播放 ≥650 次、650 仍 ≤2% 时才提示，避免误伤爬坡中的新号）</td><td>要改：让他换成自己名下的歌。这是「播放一直涨、650 永远 0%」最常见的根因之一</td></tr>
    <tr><td><span class="badge b-red">歌曲无效·查无此歌</span></td><td>网易接口查不到这首歌（已下架或已删除）</td><td>要改：换一首正常上架的歌</td></tr>
    <tr><td><span class="badge b-orange">共创歌曲·非主艺</span></td><td>这首歌是<b>多人合唱</b>，他排在第 2 位以后（主艺是别人）。实测这类号 650 恒为 0%：合唱曲里非主艺人的播放基本不计入任务</td><td>要改：优先换本人独唱的歌</td></tr>
    <tr><td><span class="badge b-orange">共创歌曲·本人主艺</span></td><td>多人合唱，他是第一艺人。比非主艺好，但播放仍会被分摊给其他艺人，不如独唱</td><td>可改可不改：能换独唱就换</td></tr>
    <tr><td><span class="badge b-orange">共创歌曲·待核</span></td><td>多人合唱，但还没同步到该号的音乐人身份，判断不了他排第几</td><td>先按「共创」处理；等元数据同步后会自动变成上面两种之一</td></tr>
    <tr><td colspan="3" style="background:#f7f7f7;font-weight:600;color:#555">B · 账号状态</td></tr>
    <tr><td><span class="badge b-yellow">待复核</span></td><td>登录已失效被系统判死，等下一轮再确认就删号</td><td>要管：让号主换 CK</td></tr>
    <tr><td><span class="badge b-yellow">未绑邮箱</span></td><td>没填通知邮箱，号失效时通知不到人</td><td>能补就补，不影响播放</td></tr>
    <tr><td><span class="badge b-gray">只收不听</span></td><td>号主自己关了互听，只接收别人的播放，不给别人播</td><td>号主的选择，不用管</td></tr>
    <tr><td><span class="badge b-gray">公益号</span></td><td><b>在编辑里手动标记的公益号</b>（也可以是没有登记歌曲的老公益号）：只帮别人听歌，自己登记的歌不再分给别人听，也不参加签到/笔记。它本来就没有 650 进度</td><td>不用管。要它回归普通号：编辑 → 账号类型选「普通号」</td></tr>
    <tr><td colspan="3" style="background:#fdf6ec;font-weight:600;color:#b85c00">C · 任务周期（650 任务本身不统计了）</td></tr>
    <tr><td><span class="badge b-orange">有播放·650为0·卡住</span></td><td>连续 2 天以上 0% 且播放量还在涨，<b>且刚刚实时查过工作台仍是 0%</b>（控制台对这类号自动做一次实时复核，30 分钟内不重复查）。实测「0%」绝大多数是<b>快照采在网易结算之前</b>：同一个号 07:20 快照 0%、11:30 实时已 100%，这类现在会被改标成灰色的「实时已恢复」</td><td>真卡住的（连续 8 天以上、实时也 0%）先让号主去音乐人后台看 650 任务还在不在；<b>后台没有「领取上期奖励 / 开启新一期」这种按钮</b>（卡片上只有「看攻略」，周期按 31 天自动换期），任务真被下掉只能重新报名或换号</td></tr>
    <tr><td><span class="badge b-orange">有播放·650为0</span></td><td>近30日播放已有 <b>650 次以上</b>，但快照里的 650 进度是 0%。<b>多半是这一轮快照早于网易结算</b>（结算窗口实测到 11:30~12:00）；控制台会自动实时复核，实时有进度就改标灰的「实时已恢复」。入池 ≤2 天的新号不标这一类</td><td>观察即可：实时复核仍是 0% 且连续 2 天以上，才升级成「·卡住」</td></tr>
    <tr><td><span class="badge b-gray">实时已恢复</span></td><td>快照里 650 是 0%，但<b>刚刚实时查工作台已经有进度</b>：这一轮快照采在网易结算之前，不是掉量也不是周期问题（同一个号 07:20 快照 0%、11:30 实时 100%）</td><td>不用管。这个标记只在被怀疑「有播放·650为0」的号上出现，30 分钟内不重复查</td></tr>
    <tr><td><span class="badge b-red">非音乐人</span></td><td>账号元数据（acc_meta）已确认该号<b>没有音乐人身份</b>：拿普通用户号登记的歌，播放永远不会计入 650（11-11 批量核查 12 个无650任务号，7 个是这类）。实习期号不会标这个 —— 实习号的音乐人身份是有的</td><td>要管：找买家核实身份 —— 要么换成音乐人号，要么按非音乐人号重新定价。让号主去后台「点开通」解决不了，因为根本没有音乐人身份</td></tr>
    <tr><td><span class="badge b-gray">无650任务</span></td><td>后台没返回 650 任务。已按账号元数据细分：有音乐人身份的 = <b>任务没开通，多为实习期未转正</b>（官方 90 天实习期里特殊权益开不了，实测实习号维持天数恒为 0、不每天涨）；转正不是纯时间驱动，有号超 90 天仍实习，可能卡在号主侧认证。元数据没同步到的保持通用提示</td><td>用「号体检」工具实时复核（能分辨非音乐人 / 实习期 / 可开通没开通三种根因）。实习期未到 90 天的等转正，超 90 天的催号主上后台查实习状态</td></tr>
    <tr><td><span class="badge b-gray">周期归零</span>（较昨日列 + 标记列）</td><td>昨日 650 已接近满（≥80%）、今天突然 0%，但近30日播放量没塌 —— 这是 <b>650 换新周期</b>，进度从头计，不是掉量。<b>周期按 31 天日历走，不看进度</b>：上期只做到 98% 到期也一样归零重来，没用完的百分比不会带到新一期</td><td>不用管：已不计入「今日下跌」，也不再标成「有播放·650为0」</td></tr>
    <tr><td colspan="3" style="background:#fdf9e6;font-weight:600;color:#8a6d00">D · 进度停滞（还在周期内，只是没动）</td></tr>
    <tr><td><span class="badge b-yellow">今日零增长</span></td><td>650 进度和昨天完全一样（还没到 100%），<b>近30日播放量也刚好持平</b>（不多不少；在跌的那种已单独标成下面的「净增≤0」）。原因基本是 <b>30 天滚动回吐</b>：悬浮说明里会给两个数 —— 该号近两周平均每天净涨多少次（=每天正常应增加的水平）、今天被多少次老播放到期退出抵掉</td><td>先观察 2~3 天，不是每天都一定涨</td></tr>
    <tr><td><span class="badge b-yellow">近30日净增≤0</span></td><td>近30日播放量今天<b>没涨或略降</b>（30 天滚动窗口），650 进度也没涨 —— 说明今天补进去的播放被 <b>30 天前那一波老播放到期退出</b>抵掉了，不是播放没算进去。只在两边快照采集时刻相差 ≤3 小时时才判（否则是拿今早的数和昨晚的数硬比）。悬浮说明里附<b>两周均值与回吐估算</b>（按该号 14 天前快照到今天的平均日增算，新号/断档没有这两个数）</td><td>偶发不用管（30 天前有过高峰的号必然会遇到一次）。连续 3 天以上净增≤0 → 说明补的量追不上退的量，加每号播放次数或换更热的歌</td></tr>
    <tr><td><span class="badge b-yellow">650未结算</span></td><td>650 进度和昨天一样，但<b>近30日播放量在涨</b>：播放已入账，网易分批结算还没滚到 650（入账窗口实测持续到 11:30~12:00）。这类不算真停滞，悬浮提示里能看到对比双方快照的采集时刻</td><td>不用管；连续 3 天以上播放量在涨而 650 不动再人工查</td></tr>
    <tr><td><span class="badge b-yellow">N天未涨</span></td><td>连续 N 天 650 进度没涨（含小幅回落；没有快照的断档天不计；当前已到 100% 的号不标）。<b>先看「近30日播放量」</b>：在跌 = 30 天滚动窗口里老播放退出（做过满 100% 的号会一直回落到新播放补不回为止，属自然衰减）；在涨却不动 = 播放被判无效</td><td>播放量也在跌 → 不用管；播放量在涨却 4 天不动 → 人工查</td></tr>
    <tr><td colspan="3" style="background:#eef5fd;font-weight:600;color:#255ea6">E · 入池状态 —— 刚进来的号，进度低是正常的，别当故障查</td></tr>
    <tr><td><span class="badge b-blue">今日入池</span></td><td>今天才登记的新号：明天才进轮转开始被听，所以今天既没有快照也没有 650 进度。<b>顶部「今日入池」这个数字就等于搜这个词的行数</b></td><td>正常，不用管（第 4 天还是 0% 再查）</td></tr>
    <tr><td><span class="badge b-green">已达100%</span></td><td>本周期 650 已经做满，继续刷也不会有额外收益</td><td>不用管；下个 31 天周期会自动归零重爬</td></tr>
    <tr><td colspan="3" style="background:#f7f7f7;font-weight:600;color:#555">F · 数据 / 其它</td></tr>
    <tr><td><span class="badge b-gray">采集缺失</span></td><td>今天这一轮没采到该号的快照（接口超时或号没跑）。<b>入池 ≤2 天的新号不会打这个标</b>（它们本来就没有快照，顶部「今日入池」就是它们的总数）</td><td>偶尔出现不用管，连续几天要查</td></tr>
    <tr><td><span class="badge b-red">只收</span>/<span class="badge b-yellow">长歌</span>（时长列）</td><td>时长 <b>2:12 以下</b>标红、<b>5:36 以上</b>标黄</td><td>只是提示，10-22 修完后长短歌都能正常计入</td></tr>
    </tbody></table>
    <b>三、号主来投诉「我的号不涨」时的排查顺序（照这个顺序问，一遍就能定位）：</b>
    <br>① <b>先看 A 组（歌曲）</b>：有「歌曲无效·绑错歌 / 歌曲无效·查无此歌 / 共创歌曲·非主艺」→ 直接是歌的问题，让他改歌，不用再查别的；
    <br>② <b>再看 B 组（账号）</b>：有「待复核」→ CK 已失效，号都要删了，先换 CK；
    <br>③ <b>再看 C 组（周期）</b>：有「有播放·650为0·卡住」→ 先看提示里的实时复核结果。<b>实时已涨</b>的（灰标「实时已恢复」）直接回「数据采早了、已经涨了」；<b>实时仍 0%</b> 的才要号主去音乐人后台确认 650 任务还在不在 —— 后台<b>没有</b>「领取上期奖励 / 开启新一期」按钮，别让号主白找（详见下面第四节）；
    <br>④ <b>再看入池天数</b>：入池 ≤2 天的号（顶部「今日入池」那批）进度低是正常爬坡，告诉他 21 天满、现在不用管；
    <br>⑤ <b>都没有</b> → 说明号是正常的，只是 650 后台分批结算（见下条）。
    <b>四、为什么没到 100% 却一天都没涨？</b>不是每天都该涨，按概率从高到低：
    <br>① <b>650 是后台分批结算的，不是实时加</b>：实测中位号一晚能跳 +30~40%，然后停一两天再突然跳一大截，所以「今天 0」很常见；
    <br>② <b>近 30 天滚动，会回吐</b>：30 天前的老播放到期退出，当天新增的有效播放少于退出的，进度就原地甚至下降（绿色负数就是这个）；
    <br>③ <b>播放 ≠ 有效播放</b>：网易按账号/IP/完整播放去重，同一个出口刷的量会被合并或丢掉。「有播放·650为0」就是这一类的信号；
    <br>④ <b>但连着 2 天以上 0% 且实时复核也是 0%，才要查任务本身</b>：650 任务是 <b>31 天一个周期、到点自动换期</b> —— 工作台返回的 <code>furtherTaskStartTime</code> 到 <code>furtherVipGetTime</code> <b>恒差 31 天</b>（11-05 抽样 9/9 都是 31.0 天），到期后进度自动归零重算，<b>不需要任何「领取 / 开启」操作</b>：任务卡片上只有「看攻略」一个按钮，抽样 <code>canOpen</code> 全是 false、<code>unlockVipRight</code> 全是 true（权益本来就是开的）。<b>「11/14 是周期结束没续期、让号主去领取上期奖励」是我们早先的误判</b>——11-05 拿这批号实时复查，8/12 当天已经是 100% 或 2~5%，只是快照采在结算之前。另外这两个时间戳在很多号上<b>停在上一个窗口不动</b>（抽样里有停在 8~9 月、进度却照常涨的），所以别拿它们判「当前周期是否到期」，看进度和实时复核就够。所以 0% 只有两种：① 网易当天结算还没跑（绝大多数，午后自己会好）；② 650 任务真被下掉/报名没成功（连续 8 天以上、实时也 0%）→ 这种只能重新报名或换号。

    <br>⑤ <b>「播放补了但总量没涨」看「净增≤0」</b>：近30日播放量是 30 天滚动窗口，今天补的播放会被 30 天前的老播放到期退出抵掉，看起来总量持平甚至略降，但播放确实补进去了。偶发一两天正常；连续 3 天以上净增≤0 才说明补的量追不上退的量，要加每号播放次数或换更热的歌。
    <br><b>所以判断号有没有问题，看「今日零增长 / 净增≤0」连续几天 + 「近30日播放量」在涨还是在跌</b>：播放量在跌且 650 也不动 = 今天补的播放被 30 天前老量退出抵消（「净增≤0」，偶发正常）；播放量在涨但 650 一直不动 = 播放被判无效（「650未结算」，连续 3 天以上才查）；650 是 0% 的先把「实时复核」结果看完再动手。
  </div></details>
  <p style="font-size:12px;color:#888;margin:10px 0 0">数据口径：<b>650进度</b>=音乐人后台 650 任务完成度（近30日滚动，会回吐，100%=达标）；<b>近30日播放量</b>=工作台播放次数（≠有效播放，≠650进度；30 天滚动，今天补的量可能被 30 天前的老量退出抵掉 → 标「净增≤0」）；<b>650 实时复核</b>=对「快照 0% 但近30日播放≥650」的号直接查一次工作台当前进度（KV 缓存 30 分钟，不写回 rate、不动任何其它列）：实时有进度标灰「实时已恢复」，实时仍 0% 才继续标「有播放·650为0」；<b>较昨日</b>=今天快照-昨天快照，前一日无快照显示 —（数据断层，非故障；<b>今晚听歌</b>=按当前号池回放的今晚计划（每号本群歌单首数，已配平；加速档每天每首歌要几个听众，被稀释时标红）；顶部每个统计名的用词与标记列完全一致，搜索框直接搜那个词就能筛出对应行）；昨日≥80% 今日 0% 且播放量没塌的显示为灰色「周期归零」= 650 换新周期不是掉量（已从「今日下跌」剔除）；<b>笔记任务</b>=与 650 无关的同组小任务（发布图文笔记，按「已发x/4」显示：30 天内发布图文笔记天数≥4，4/4 即完成），显示 — 表示只有 650 一个任务；<b>时长</b>=登记歌曲长度（红=短歌&lt;2:12、黄=长歌&gt;5:36，仅提示，10-22 修完后都能正常计入）；<b>今日进度下的小字</b>=该行快照采集时间（北京时间；凌晨轮次边跑边采，不代表当天最终值，11:40 主采后的数才准）；各标记含义见上方「标记看不懂」对照表。<b>运行状态横条</b>：作业=两仓库最近一次定时轮次（GitHub API，5 分钟缓存）；应跑/实跑=按当前号池对所选日期回放的轮转计划与 runs 表核对（历史日期为近似值）；快照更新=该日快照最后写入时间（北京时间）；今日删号/待复核来自 D1。</p>
</div>
<div class="modal" id="modal" hidden><div class="mbox">
  <h3 id="mTitle">编辑账号</h3><p style="font-size:12px;color:#888;margin:4px 0 0" id="mSub"></p>
  <label>改绑歌曲（粘贴 APP 分享链接，留空不改）</label><input id="eLink" placeholder="https://163.com/... 或 song?id=...">
  <label>通知邮箱（留空不改）</label><input id="eEmail">
  <label>客服（谁录的这条，留空不改）</label><select id="eAgent"><option value="">不修改</option></select>
  <label>套餐（登记时买的时长，留空不改；<b>改套餐不会自动改有效期</b>，要一起改就把下面有效期也填上）</label>
  <select id="ePlan"><option value="">不修改</option></select>
  <label>有效期（天数 / 日期 / 永久，留空不改）</label><input id="eExp">
  <label>暂停互听（只收不听）</label><select id="eNo"><option value="">不修改</option><option value="0">参与互听</option><option value="1">暂停互听</option></select>
  <!-- ===== 2026-11-05：备注 + 补号 ===== -->
  <div style="margin-top:14px;padding:10px 12px;background:#f7f9fb;border:1px solid #e6ebf1;border-radius:10px">
    <label style="margin-top:0">备注（内部记录，号主看不到）</label>
    <input id="eNote" maxlength="200" placeholder="例：11月原号 138xxxx 掉线，免费补登">
    <label>补号标记（客户掉线后免费补的新号：<b>不计营收、不给客服提成</b>）</label>
    <select id="eRb"><option value="">不修改</option><option value="1">是补号（免费补偿，不算钱）</option><option value="0">改成正常单（算钱）</option></select>
    <p style="font-size:12px;color:#666;margin:6px 0 0" id="rbNow"></p>
    <div id="rbBox" hidden style="margin-top:8px;border-top:1px dashed #dde3ea;padding-top:8px">
      <label style="margin-top:0">① 找原单（填手机号 / 原网易 UID，原号早被删了也能查到）</label>
      <div style="display:flex;gap:8px">
        <input id="rbQ" placeholder="如 13800138000" style="flex:1">
        <button class="mini" id="rbFind" type="button" style="margin-top:0">查原单</button>
      </div>
      <div id="rbList" style="max-height:160px;overflow:auto;margin-top:6px;font-size:12.5px"></div>
      <label>② 原单登记日（填了就自动算继承到期日）</label>
      <input id="rbStart" placeholder="YYYY-MM-DD">
      <p style="font-size:11.5px;color:#888;margin:6px 0 0" id="rbHint">到期日 = 原单登记日 + 本单套餐天数。这样客户不会因为补号白得剩下的月份；想手工指定到期日，就填上面的「有效期」，以你填的为准。</p>
      <input type="hidden" id="rbFrom">
    </div>
  </div>
  <label>账号类型（公益号 = 只帮别人听歌，自己登记的歌不再分给别人听，也不签到）</label><select id="ePub"><option value="">不修改</option><option value="0">普通号（参加互听 + 签到）</option><option value="1">公益号（只帮别人听）</option></select>
  <label>更换 CK（MUSIC_U，留空不改；保存前服务端会先校验有效性）</label><input id="eCk" placeholder="粘贴新的 MUSIC_U 值">
  <div class="row2"><button id="eSave">保存修改</button><button class="warn" id="eDel">删除账号</button><button class="gray" id="eCancel">关闭</button></div>
  <div class="msg" id="em"></div>
</div></div>
<div class="modal" id="cfgModal" hidden><div class="mbox">
  <h3>客服名单 / 套餐档位</h3>
  <p style="font-size:12px;color:#888;margin:4px 0 0">改完保存立即生效：APK / EXE 下次登记前会自动拉到新名单，<b>不用重新打包</b>。只读口令进不来这一页。</p>
  <div style="border:1px solid #f3e2c8;background:#fffaf1;border-radius:9px;padding:10px 12px;margin:10px 0 12px">
    <div style="font-size:12.5px;font-weight:600;color:#8a6a3a;margin-bottom:7px">客服改名（名单 + 已登记的号 + 结算账本，一次全换）</div>
    <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap">
      <div><label style="margin-top:0">原名字</label><select id="rnOld" style="width:150px"></select></div>
      <div><label style="margin-top:0">改成</label><input id="rnNew" placeholder="新名字" style="width:150px"></div>
      <button class="mini" id="rnGo" style="margin-top:0;padding:9px 14px">执行改名</button>
    </div>
    <p style="font-size:11.5px;color:#96714a;margin:8px 0 0;line-height:1.7">⚠ 不要在下面的名单框里直接改字 —— 那只换了登记的<b>下拉选项</b>，<b>已登记的号和已经结算过的订单仍是旧名字</b>，而且系统分不清你是「改名」还是「删掉一个 + 新增一个」。要改名就用这里。</p>
  </div>
  <label>客服（一行一个，格式 <code>客服名</code> 或 <code>客服名|售后群号</code>；顺序即下拉顺序）</label>
  <textarea id="cAgents" rows="5" style="width:100%;box-sizing:border-box;padding:9px;border:1px solid #ddd;border-radius:8px;font-size:13px;font-family:ui-monospace,Consolas,monospace"></textarea>
  <p style="font-size:11.5px;color:#999;margin:6px 0 0">群号给登记成功邮件和到期提醒用（例：<code>徐|1129937451</code>）。不写竖线 = 该客服没配群号，邮件里会引导客户自己找客服。<br>下面的默认群号：老账号没记客服名时兜底用，留空 = 不兜底。</p>
  <label style="margin-top:8px">默认售后群号（老号没记客服名时兜底，可留空）</label>
  <input id="cDefGrp" inputmode="numeric" placeholder="如 1129937451" style="width:220px">
  <label>套餐（一行一个，格式 <code>显示名=天数=单价</code>；天数填 0 表示永久，单价单位元）</label>
  <textarea id="cPlans" rows="6" style="width:100%;box-sizing:border-box;padding:9px;border:1px solid #ddd;border-radius:8px;font-size:13px;font-family:ui-monospace,Consolas,monospace"></textarea>
  <p style="font-size:11.5px;color:#999;margin:6px 0 0">例：<code>1月=30=3</code> / <code>半年=180=10</code> / <code>1年=365=15</code> / <code>2年=730=20</code> / <code>永久=0=80</code>。<br>单价的第三段不写就等于「没定价」，月度结算里会把它单列成「待补价」，<b>不会当 0 元算进合计</b>。删掉某个套餐不影响已登记的号（它们的套餐名照旧显示）。</p>
  <div class="row2"><button id="cSave">保存</button><button class="gray" id="cCancel">关闭</button></div>
  <div class="msg" id="cm"></div>
</div></div>
<!-- ===== 2026-11-10：客服机器授权 ===== -->
<div class="modal" id="devModal" hidden><div class="mbox" style="width:880px;max-height:90vh;overflow:auto">
  <h3>设备授权（客服电脑）</h3>
  <p style="font-size:12px;color:#888;margin:4px 0 0;line-height:1.75">新版客服软件第一次生成链接会报出自己的<b>机器码</b>，这里授权以后那台电脑才能继续生成。<br>
  <b>待授权</b>的机器从第一次出现起有 <b>24 小时</b>宽限，超时没授权就会被拦住，并提示客服把机器码发给管理员。<br>
  每台机器可以单独设每日上限（留空按 200）。<b>停用</b> = 立刻拦住但保留记录；<b>删除</b> = 彻底忘掉，下次再出现会重新变成待授权。<br>
  ⚠ 机器码能挡住「软件被传到网上、陌生人下载就用」，<b>挡不住会逆向的人</b>（算法和口令都在软件里）。要彻底防白嫖得改成每个客服独立账号。</p>
  <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;margin:12px 0 6px;padding:10px 12px;background:#fffaf1;border:1px solid #f3e2c8;border-radius:9px">
    <div><label style="margin-top:0">机器码</label><input id="dvCode" placeholder="如 A3F92K7Q8M1D" style="width:175px;font-family:ui-monospace,Consolas,monospace"></div>
    <div><label style="margin-top:0">归哪个客服</label><select id="dvAgent" style="width:130px"></select></div>
    <div><label style="margin-top:0">每日上限</label><input id="dvQuota" value="200" inputmode="numeric" style="width:88px"></div>
    <button class="mini" id="dvAdd" style="margin-top:0;padding:9px 14px">添加 / 授权</button>
    <button class="mini gray" id="dvReload" style="margin-top:0">刷新</button>
  </div>
  <div id="dvBody"></div>
  <div class="row2"><button class="gray" id="dvClose">关闭</button></div>
  <div class="msg" id="dvm"></div>
</div></div>
<!-- ===== 2026-11-10：登记链接（新登记 / 续费 / 补登） ===== -->
<div class="modal" id="rgModal" hidden><div class="mbox" style="width:880px;max-height:92vh;overflow:auto">
  <h3>登记链接（发链接给买家，让他自己扫码登记）</h3>
  <p style="font-size:12px;color:#888;margin:4px 0 0;line-height:1.75">
  <b>三种类型不能混用：</b><br>
  · <b>新登记</b> —— 新客户。收钱、算提成，到期日 = 今天 + 套餐天数。<br>
  · <b>续费</b> —— 老客户付钱延期。收钱、算提成，到期日 = <b>原到期日 + 套餐天数</b>（剩下的一天天都不丢）；号已经掉线也能用，会以原单到期日为基准累加。<br>
  · <b>补登</b> —— 号掉线了，免费补回。不收钱、不算提成，到期日<b>继承原单</b>（不延长）。<br>
  ⚠ 续费和补登<b>必须先搜到原单</b>：类型是定在链接上的，客户后来换手机号、换网易号都不影响判定。原单已过期的不能补登（补登只在原套餐有效期内免费）。</p>
  <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;margin:12px 0 6px;padding:10px 12px;background:#fffaf1;border:1px solid #f3e2c8;border-radius:9px">
    <div><label style="margin-top:0">类型</label><select id="rgKind" style="width:120px"><option value="new">新登记</option><option value="renew">续费</option><option value="fix">补登（免费）</option></select></div>
    <div><label style="margin-top:0">客服</label><select id="rgAgent" style="width:110px"></select></div>
    <div><label style="margin-top:0">套餐</label><select id="rgPlan" style="width:110px"></select>
      <div id="rgPlanTip" hidden style="font-size:11px;color:#b06a00;margin-top:2px">补登继承原单，不用选</div></div>
    <div><label style="margin-top:0">链接有效期</label><select id="rgHours" style="width:110px"><option value="24">24 小时</option><option value="72">3 天</option></select></div>
  </div>
  <div id="rgRefBox" hidden style="margin:0 0 10px;padding:10px 12px;background:#f6f9ff;border:1px solid #dbe6fb;border-radius:9px">
    <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap">
      <div><label style="margin-top:0">原单（客户手机号 或 网易 UID）</label><input id="rgRef" placeholder="如 13800138000 或 1234567890" style="width:250px" inputmode="numeric"></div>
      <button class="mini gray" id="rgFind" style="margin-top:0">搜索原单</button>
    </div>
    <div id="rgRefOut" style="margin-top:8px"></div>
  </div>
  <div><label>备注（买家看不到，只记在这条链接上，方便你自己认）</label><input id="rgNote" maxlength="60" placeholder="如：11月 张先生 号掉线补登"></div>
  <div class="row2"><button id="rgGo">生成链接</button><button class="gray" id="rgClose">关闭</button></div>
  <div class="msg" id="rgm"></div>
  <div id="rgOut"></div>
  <div style="display:flex;gap:8px;align-items:center;margin:16px 0 6px;flex-wrap:wrap">
    <h4 style="margin:0;font-size:13px">最近生成</h4>
    <!-- 2026-11-10：原来只有「未使用/已使用/已作废」看起来像没有过期这一档。
         已过期是算出来的（state 仍是 unused、exp_at 过了），服务端已支持筛选。 -->
    <select id="rgState" style="width:130px;font-size:12px;padding:4px 6px">
      <option value="">全部状态</option>
      <option value="unused">未使用（未过期）</option>
      <option value="expired">已过期</option>
      <option value="used">已使用</option>
      <option value="void">已作废</option>
    </select>
    <!-- 2026-11-11：链接查询（与 APK / EXE 同一套 q 参数）。粘整条链接、填 8 位编码、
         或填客户手机号都认；查询是服务端真查（编码走主键、手机号走 phone 条件），
         不是在这 25 条里过滤，老链接也查得到。 -->
    <input id="rgQ" placeholder="查询：粘链接 / 编码或手机号的任意几位（≥3 位）" style="flex:1;min-width:190px;font-size:12px;padding:5px 8px;border:1px solid #ddd;border-radius:6px">
    <button class="mini" id="rgQBt" style="margin-top:0">查询</button>
    <button class="mini gray" id="rgQAll" style="margin-top:0">显示全部</button>
  </div>
  <div id="rgList"></div>
</div></div>
<!-- ===== 2026-11-05：月度结算 ===== -->
<div class="modal" id="lgModal" hidden><div class="mbox" style="width:980px;max-height:92vh;overflow:hidden;display:flex;flex-direction:column">
  <h3>月度结算</h3>
  <p style="font-size:11.5px;color:#8a8a8a;margin:6px 0 0;line-height:1.65">按<b>登记月</b>算：谁在哪个月录的号、买了什么套餐、一共多少钱。跟这个号现在还在不在、套餐后来有没有改过都无关（底账是成交流水，登记那一刻就固定了）。<br><b>退单</b>（成交后号被删）不计收入、不计提成；补号单、公益赠号/手动号也都不计营收、不计提成，各自单列。</p>
  <div style="display:flex;gap:10px;align-items:flex-end;margin-top:10px;flex-wrap:wrap">
    <div><label style="margin-top:0">月份</label><input type="month" id="lgMonth" style="width:150px"></div>
    <div><label style="margin-top:0">群</label><select id="lgPool" style="width:130px"><option value="hz" selected>主群</option><option value="">全部（含定制群）</option><option value="dz">定制群</option></select></div>
    <div><label style="margin-top:0">客服</label><select id="lgAgent" style="width:160px"><option value="">全部客服</option></select></div>
    <button class="mini" id="lgGo" style="margin-top:0;padding:9px 16px">查询</button>
    <button class="mini gray" id="lgCsv" style="margin-top:0">导出明细CSV</button>
  </div>
  <div id="lgBody" style="margin-top:12px;font-size:13px;flex:1;min-height:0;overflow:auto"></div>
  <div class="row2"><button class="gray" id="lgClose">关闭</button></div>
  <div class="msg" id="lgm"></div>
</div></div>
<script>
var TOKEN=null, DATA=null, POOLF='all';
// 2026-10-27：ROLE='full' 满权限 / 'ro' 只读（只能看，编辑、删号、客服名单全部关掉）。
// AGENTF/PLANF 是客服/套餐筛选值；AGENTS/PLANS 来自服务端 reg_cfg（控制台可改，不用重发软件）。
// STATF（2026-11-05）：顶部统计卡点出来的筛选值。空串=不筛；'__xxx' 是特殊口径（总数/有数据/上涨/下跌/3天+未涨），
// 其它值直接当行内标记文本用（和搜索框同一套匹配，所以「顶部有数、点开搜不到」的老问题不会再出现）。
var ROLE='ro', AGENTF='', PLANF='', STATF='', AGENTS=[], PLANS=[];
// 2026-11-05：编辑弹窗是否成功回填到该行数据。true 才提交备注（否则「留空」会被当成清空）。
var NOTE_OK=false;
function $(id){return document.getElementById(id);}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function todayBJ(){var d=new Date(Date.now()+8*3600*1000);return d.toISOString().slice(0,10);}
// 2026-10-27：日期范围要算「前一天」，不能再用本地时区做减法（会跨时区错一天），
// 统一按 UTC 拼日期再减，结果仍是 yyyy-mm-dd。
function dMinus(day,n){
  if(!day)return '';
  var p=String(day).split('-');
  if(p.length!==3)return '';
  var d=new Date(Date.UTC(+p[0],+p[1]-1,+p[2]));
  d.setUTCDate(d.getUTCDate()-(n||1));
  return d.toISOString().slice(0,10);
}
// 2026-11-05：日期 +n 天（补号继承到期日的前端预览用，必须与服务端 datePlusFrom 算得一样）
function dAdd(day,n){
  if(!day)return '';
  var p=String(day).split('-');
  if(p.length!==3)return '';
  var d=new Date(Date.UTC(+p[0],+p[1]-1,+p[2]));
  d.setUTCDate(d.getUTCDate()+(n||0));
  return d.toISOString().slice(0,10);
}
function api(ep,body){return fetch(ep,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});});}
// 2026-10-28（用户要求：输一次就一直有效）：控制台口令重新落盘记忆。
// 上一版是「每次都输」，理由是别把 24 位口令明文留在浏览器里；实际用下来太麻烦，改回记忆。
// 现在：登录成功 → 把 {user,pass} 连带 role 一起存进 localStorage 的 consToken。
//   存 role 是为了刷新时立刻恢复「满权限 / 只读」标签，不用等 data 回来再闪一下。
// 失效兜底：KV 里换过口令后，旧 token 请求 /api/console/data 会 403 →
//   loadData 里 dropTok() 并弹回登录框，不会卡在「一直自动登录失败」的死循环。
// 想主动清掉：点右上「退出」，走 dropTok() 删本地 token。
var TOK_KEY='consToken';
function save(t,role){
  TOKEN=t;
  var rec={t:t,role:role||""};
  try{localStorage.setItem(TOK_KEY,JSON.stringify(rec));}catch(e){}
  try{sessionStorage.removeItem(TOK_KEY);}catch(e){}
}
function load(){
  try{
    var raw=localStorage.getItem(TOK_KEY);
    if(!raw)return null;
    var rec=JSON.parse(raw);
    if(!rec||!rec.t)return null;              // 老版本残留（直接存 {user,pass}）= 认不出，重登一次
    var p=JSON.parse(rec.t);                  // token 本身仍是 {user,pass} 的 JSON 串
    if(!p||!p.user||!p.pass)return null;
    return {t:rec.t,role:rec.role||""};
  }catch(e){return null;}
}
/* 2026-11-11 v2.12：dropTok 此前被引用（退出按钮、密码错兜底）却从没定义过 ——
   点「退出」直接抛 ReferenceError，表现就是「没有任何反应」。这里补上：
   清 localStorage 的 token + 清内存 TOKEN。 */
function dropTok(){
  try{localStorage.removeItem(TOK_KEY);}catch(e){}
  try{sessionStorage.removeItem(TOK_KEY);}catch(e){}
  TOKEN=null;
}
function login(){
  var u='xx1031',p=$('lp').value;   // 2026-10-25：账号固定，登录框只留口令一个输入框
  if(!u||!p){$('lm').textContent='请输入账号和密码';$('lm').className='msg err';return;}
  $('lbtn').disabled=true;
  api('/api/console/login',{user:u,pass:p}).then(function(o){
    $('lbtn').disabled=false;
    if(o.ok&&o.d.ok){TOKEN=JSON.stringify({user:u,pass:p});save(TOKEN,o.d.role);$('loginBox').hidden=true;$('mainBox').hidden=false;applyRole(o.d.role);loadData(true);}
    else{$('lm').textContent=(o.d&&o.d.message)||'登录失败';$('lm').className='msg err';}
  }).catch(function(){$('lbtn').disabled=false;$('lm').textContent='网络错误';$('lm').className='msg err';});
}
$('lbtn').onclick=login;
$('lp').onkeydown=function(e){if(e.key==='Enter')login();};
$('lu').onkeydown=function(e){if(e.key==='Enter')$('lp').focus();};
/* 2026-11-11 v2.12：退出要通知宿主页（APK 把控制台嵌在 iframe 里，权限码还存在
   宿主 ck.html 的 localStorage 里 —— 只清自己的 token，宿主下次又带 #pw= 免密进来，
   表现就是「点了退出没反应」。postMessage 通知宿主清掉存的权限码并重新弹输入框；
   独立浏览器标签里 parent 就是自己或没有监听者，发了也无害。 */
$('btnOut').onclick=function(){
  try{if(window.parent&&window.parent!==window)window.parent.postMessage('console-logout','*');}catch(e){}
  dropTok();
  location.reload();
};
$('btnRefresh').onclick=function(){loadData(true);};   // 2026-11-09：点刷新 = 强制回源，不再命中 5 分钟缓存
// 2026-10-27 21:05：入池筛选是纯前端，改日期直接 render，不再重新请求接口（秒出）
$('date').onchange=render;$('dateTo').onchange=render;
$('dClear').onclick=function(){$('date').value='';$('dateTo').value='';render();};
$('q').oninput=render;$('sort').onchange=render;
$('fagent').onchange=function(){AGENTF=this.value;render();};
$('fplan').onchange=function(){PLANF=this.value;render();};
// 2026-11-05：顶部统计卡点击 = 按这一项筛选（再点一次取消）。用 data-sv + 事件委托，
// 不写内联 onclick —— 这段脚本住在模板字符串里，内联写法要跨两层转义，10-27 因而崩过整段脚本。
// 监听挂在 #stats 容器上，卡片本身每次 render 都重画也不影响。
$('stats').onclick=function(ev){
  var el=ev.target;
  while(el&&el!==this&&!(el.getAttribute&&el.getAttribute('data-sv')))el=el.parentNode;
  if(!el||el===this||!el.getAttribute)return;
  pickStat(el.getAttribute('data-sv'));
};
// 2026-10-27 二次改：入池范围控件已删（用户不要）。两个日期框都要重新拉数据，
// 因为起止日直接决定取哪两天的快照，纯前端过滤做不到。
// 2026-10-24：表格区高度自适应视口剩余空间 → 滚动发生在 .twrap 内部，配合 .twrap th 的 sticky 实现表头冻结
// 2026-10-26 修（手机端排版错乱）：手机宽度下表格已改成卡片流、整页滚动，这里绝不能再锁高度。
//   原来这里无条件写 w.style.maxHeight，手机上 innerHeight 减掉页头/统计/工具条后只剩 100 多 px，
//   被兜到 240px —— 437 张卡片全被塞进 240px 的盒子里溢出，后面的「删号记录 / 标记对照表 / 底部说明」
//   就按 240px 的位置排版，直接压在账号卡片上（用户 10-26 截图里的错乱就是这个）。
function fitTable(){
  var w=document.querySelector('.twrap');if(!w)return;
  if(window.innerWidth<=860||!w.offsetParent){w.style.maxHeight='';return;}
  var docTop=w.getBoundingClientRect().top+(window.pageYOffset||0);
  var h=window.innerHeight-docTop-18;
  w.style.maxHeight=(h>240?h:240)+'px';
}
window.addEventListener('resize',fitTable);
document.querySelectorAll('.tab').forEach(function(t){t.onclick=function(){
  document.querySelectorAll('.tab').forEach(function(x){x.classList.remove('on');});
  t.classList.add('on');POOLF=t.getAttribute('data-p');render();};});
function accsOf(day,pool){
  // 2026-10-23 修复：/api/console/data 返回的 snap 是 {cur:{hz,dz},prev:{hz,dz}}，
  // 这里原来按 snap[日期][池] 取 → 取不到，a/p 恒为 null，
  // 导致「昨进度 / 今进度 / 日环比 / 近30日播放 / 任务」五列全空、今日有数据恒为 0。
  var S=DATA.snap||{};
  // 2026-11-07：加 S.old（14 天前快照）—— 给「今日零增长 / 净增≤0」标记算两周平均日增与回吐估算。
  if(S.cur||S.prev||S.old){var src=(day&&day===DATA.oldDate)?S.old:((day&&day===DATA.prevDate)?S.prev:S.cur);return (src&&src[pool])||{};}
  return (S[day]&&S[day][pool])||{};
}
// ===== 2026-10-27：客服名单 / 套餐档位（服务端 reg_cfg）=====
// 下拉选项全部由服务端给，页面里不写死任何人名 —— 加人/停人只改一次配置。
function fillSel(el,items,keep,allLabel){
  var h='';
  if(allLabel!=null)h+='<option value="">'+esc(allLabel)+'</option>';
  else h+='<option value="">不修改</option>';
  h+=items.map(function(v){return '<option value="'+esc(v)+'">'+esc(v)+'</option>';}).join('');
  el.innerHTML=h;
  el.value=items.indexOf(keep)>=0?keep:'';
  return el.value;
}
function applyCfg(cfg){
  cfg=cfg||{};
  AGENTS=(cfg.agents||[]).slice();
  PLANS=(cfg.plans||[]).slice();
  AGENTF=fillSel($('fagent'),AGENTS,AGENTF,'客服：全部');
  var labels=PLANS.map(function(p){return p.label;});
  PLANF=fillSel($('fplan'),labels,PLANF,'套餐：全部');
  fillSel($('eAgent'),AGENTS,'',null);
  fillSel($('ePlan'),labels,'',null);
}
// 只读口令进来：所有写入口关掉。真正的拦截在服务端（写接口只认满权限口令），
// 前端这层只是不让人白点、也不给误操作的机会。
function applyRole(role){
  ROLE=(role==='full')?'full':'ro';
  var full=(ROLE==='full');
  $('btnCfg').style.display=full?'':'none';
  $('btnDev').style.display=full?'':'none';
  // 2026-11-10：登记链接（含补登/续费）只有满权限能生成，服务端同样只认满权限口令
  var brg=$('btnReg');if(brg)brg.style.display=full?'':'none';
  // 2026-11-05：结算涉及金额，只有满权限能看到入口（服务端也拦）
  var bl=$('btnLedger');if(bl)bl.style.display=full?'':'none';
  var t=$('ptitle');
  if(t){
    var old=document.getElementById('roTag');
    if(old)old.parentNode.removeChild(old);
    if(!full){
      var s=document.createElement('span');
      s.id='roTag';s.className='ro';s.textContent='只读';
      s.title='你现在用的是只读口令：可以看全部数据、可以导出，但不能改任何东西';
      t.appendChild(s);
    }
  }
}
// 2026-10-27 21:05 三次改：顶部两个日期框 = **入池日期范围**（不是快照日期）。
// 上一版把它们当「650 快照取哪两天」，结果用户选完区间表格几乎没变化 —— 因为两天快照本来
// 就长得差不多。改成按账号的 added（入池日）筛，行数立刻能看出差别。
//   · 两个都空 → 全部（跟最早的单日视图一样，不筛）
//   · 只填左边 → 这天及以后入池的
//   · 只填右边 → 这天及以前入池的
//   · 填反了自动对调（写回输入框，让用户看见实际生效的范围）
// 650 进度两列固定「昨天 vs 今天」，不再跟日期框联动。
function drngOf(){
  var a=$('date').value||'',b=$('dateTo').value||'';
  if(a&&b&&a>b){var x=a;a=b;b=x;$('date').value=a;$('dateTo').value=b;}
  return {from:a,to:b};
}
function loadData(force){
  var t=JSON.parse(TOKEN||'{}');
  var b=$('btnRefresh');var bt=b.textContent;
  b.disabled=true;b.textContent='刷新中…';
  var q={user:t.user,pass:t.pass};
  // 2026-11-09：点「刷新」必须真的回源。服务端 /api/console/data 本来就支持 body.nocache=1
  // 强制跳过 KV 缓存，但前端从来没传过 —— 于是 5 分钟内点第二次拿到的是同一份缓存，
  // 数据一格都不会变（用户反馈「刷新没用」）。
  // 现在的分工：点刷新 / 登录进来 = 强制取最新；登记、改配置、删号后的自动 reload 走缓存
  // （那些动作本身会 bump cc:ver，该失效的照样失效）。
  if(force)q.nocache=1;
  // 2026-10-27 21:05：不传 date/prevDate —— 后端默认就是「昨天 vs 今天」。
  // 日期框改成筛入池日期了，再往这里塞会把筛选值污染成快照日期。
  api('/api/console/data',q).then(function(o){
    b.disabled=false;b.textContent=bt;
    if(!o.ok){if(((o.d&&o.d.message)||'').indexOf('密码')>=0){dropTok();TOKEN=null;}$('lm').textContent=o.d.message||'请重新登录';$('lm').className='msg err';$('loginBox').hidden=false;$('mainBox').hidden=true;return;}
    DATA=o.d;
    applyCfg(DATA.cfg);           // 客服/套餐下拉 + 汇总口径
    applyRole(DATA.role);         // 满权限 / 只读（服务端 data 里带，刷新一次就恢复正确权限）
    render();fitTable();
  }).catch(function(){
    // 2026-11-09：原来这里静默吞错，请求超时/5xx 时页面毫无反应，用户以为刷完了。
    b.disabled=false;b.textContent='刷新失败';
    setTimeout(function(){b.textContent=bt;},2500);
  });
}
// 2026-10-24：网易工作台只回 missionCode + progressRate 两个原始字段，不翻译就是一串天书；
// 而且原来把「650 主任务」和「发布笔记」两个代码拼在一格还带 CSS 截断，看着像 650 只有 2%。
var MAIN_MISSION='mission_code_recently_play_effect_count_v2';   // 650 有效播放，与「今日650进度」列同一个数
var MIS_NAME={mission_code_musician_notebook_publish:'发布笔记'};  // 网易同组小任务，与播放无关
// 2026-10-25：progressRate 不是统一的百分比。原始接口每个子任务都带 totalCompleteNum：
// 650 主任务 totalCompleteNum=100 → progressRate 是 0~100 的百分比；
// 「发布笔记」totalCompleteNum=4（即日起30天内发布图文笔记天数≥4）→ progressRate 是
// 已发条数 0~4（全池快照实测只有 0/1/2/3/4 四个离散值）。
// 原来一律拼个 % 上去，「已发 4 条 = 4/4 早就完成」被显示成「4%」，看着像还没开始。
// 计数型任务在这里登记目标值，页面渲染成 x/4；没登记的目标值仍按百分比显示（保持旧行为）。
var MIS_TOTAL={mission_code_musician_notebook_publish:4};   // 网易任务目标值（条/天，非百分比）
function misName(k){if(MIS_NAME[k])return MIS_NAME[k];return String(k).replace(/^mission_code_/,'').replace(/_v\\d+$/,'').replace(/_/g,' ');}
// 「笔记任务」列：650 主任务已在进度列显示，这里只列其余小任务（当前就是发布笔记）并译成中文；没有就显示 —
function otherMis(a){
  if(!a||!a.mis)return '<span class="flat">—</span>';
  var h='';
  Object.keys(a.mis).forEach(function(k){
    if(k===MAIN_MISSION)return;
    var v=a.mis[k],t=MIS_TOTAL[k];
    h+='<span class="mtag">'+esc(misName(k))+' <i>'+(t?v+'/'+t:v+'%')+'</i></span>';
  });
  return h||'<span class="flat">—</span>';
}
// ===== 2026-10-25：售后诊断标签 =====
// 目标：号主来问「我这号怎么不涨/怎么归零了」，客服看这列就能直接说出原因，不用现查。
// 分组优先级（同组只出一个，避免一个号挂 5 个标签看不清）：
//   A 歌曲问题（红/橙） > B 任务周期（橙） > C 账号状态（黄） > D 入池进度（灰蓝） > E 数据（灰）
// 数据源：DATA.songs（song_meta）与 DATA.artists（acc_meta），由 tmp/sync_song_meta.py 定期回填。
var DAY_MS = 86400000;
// 入池天数：登记当天算 0（次日才开始被听）
function daysSince(added) {
  // 2026-10-30：added 可能是 'YYYY-MM-DD HH:MM:SS'（新）或 'YYYY-MM-DD'（老），统一取日期部分
  var ad = String(added || '').slice(0, 10);
  if (!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(ad)) return null;
  var a = Date.parse(ad + 'T00:00:00Z'), t = Date.parse(String(DATA && DATA.date) + 'T00:00:00Z');
  if (isNaN(a) || isNaN(t)) return null;
  return Math.round((t - a) / DAY_MS);
}
// 歌曲归属研判 → 返回 {cls, txt, tip} 或 null
// 判据：歌曲作者数 n；本人音乐人 id 是否在作者列表里、排第几
function songVerdict(e, a) {
  var s = (DATA && DATA.songs) || {}, art = (DATA && DATA.artists) || {};
  var m = s[String(e.song)];
  if (!m) return null;                       // 元数据还没同步到这首 → 不打标签（不猜）
  if (m.g === 1) return { cls: 'b-red', txt: '歌曲无效·查无此歌',
    tip: '网易接口查不到这首歌（song_id ' + e.song + '）：已下架或已删除。播放不会进 650，让号主重新登记一首名下正常上架的独唱歌曲' };
  // 2026-10-25 补：独唱也可能「绑错歌」——这首歌只有 1 位作者，但那位作者不是该号的音乐人身份，
  // 播放同样永远不算进他的 650。为免误伤正常爬坡的新号，只在「近30日播放≥650 次却仍是 0%」时才提示。
  if ((m.n || 0) <= 1) {
    var me1 = art[String(e.uid)], only = (m.i || [])[0] || '', soloId = me1 ? (me1[0] || '') : '';
    if (soloId && only && only !== soloId && a && (a.rate || 0) <= 2 && (a.rpc30 || 0) >= 650)
      return { cls: 'b-red', txt: '歌曲无效·绑错歌',
        tip: '这首是独唱，唯一作者「' + (m.f || '—') + '」不是该号的音乐人「' + (me1[1] || soloId) + '」→ 近30日播放 ' + a.rpc30 + ' 次、650 却只有 ' + (a.rate || 0) + '%，播放基本没算到该号头上。让号主改绑到他自己名下已上架的独唱歌曲' };
    return null;                             // 独唱且作者对得上：正常，不打标签（页面上不堆无意义的绿标）
  }
  var me = art[String(e.uid)];
  if (!me) return { cls: 'b-orange', txt: '共创歌曲·待核',
    tip: '这首歌是 ' + m.n + ' 人合唱（主艺：' + (m.f || '—') + '），但还没同步到该号自己的音乐人身份，暂时判断不了他排第几。可先按「共创歌曲」处理：合唱曲里非主艺人的播放通常不算进 650，建议换一首本人独唱的歌' };
  var myId = me[0] || '';
  if (!myId) return null;                    // 该号不是音乐人 → 交给「无650任务」标签，别重复报
  var pos = (m.i || []).indexOf(myId);
  if (pos < 0) return { cls: 'b-red', txt: '歌曲无效·绑错歌',
    tip: '这首歌《' + (m.f || '') + '…》的 ' + m.n + ' 位作者里没有该号的音乐人身份（' + (me[1] || myId) + '）→ 播放再多也永远不会算进他的 650。必须改绑到他自己名下的歌' };
  if (pos > 0) return { cls: 'b-orange', txt: '共创歌曲·非主艺',
    tip: '这是 ' + m.n + ' 人合唱，该号排第 ' + (pos + 1) + ' 位（主艺是「' + (m.f || '—') + '」）。实测这类号 650 恒为 0%：合唱曲里非主艺人的播放基本不计入任务，建议改绑本人独唱的歌' };
  return { cls: 'b-orange', txt: '共创歌曲·本人主艺',
    tip: '这是 ' + m.n + ' 人合唱，该号是第一艺人。比非主艺好，但仍比独唱差（播放会被分摊到其他艺人），能换独唱就换' };
}

function buildRows(){
  if(!DATA)return[];
  var cur=DATA.snap.cur,prev=DATA.snap.prev,rows=[];
  [['hz',DATA.hz],['dz',DATA.dz]].forEach(function(pd){
    var pool=pd[0];
    pd[1].forEach(function(e){
      // 2026-11-07：o = 14 天前快照（DATA.oldDate 由后端给，老缓存响应没有这个键时 accsOf 回落 S.cur → 取不到 → o 为 null，标记自动降级为不带数字的老文案）
      var a=accsOf(DATA.date,pool)[e.uid]||null,p=accsOf(DATA.prevDate,pool)[e.uid]||null,o=accsOf(DATA.oldDate,pool)[e.uid]||null;
      var delta=(a&&p&&a.rate!=null&&p.rate!=null)?(a.rate-p.rate):null;
      // 2026-10-25：周期归零判定 —— 昨日已接近满(≥80%)、今天突然 0%，但近30日播放量没塌(仍有昨日90%以上)。
      // 这是 650 任务换新周期（进度重新从 0 起算），不是掉量，不该算进「今日下跌」、也不该显示成 -100。
      // 2026-10-26 ⚠️ 实测否决：一度想改用工作台的 furtherVipGetTime（存于 DATA.periods）精确判定，
      //   但 10-26 全池实测把它证伪了 —— 按该字段「已过期」的 131 个号里 125 个当天仍在涨（95%），
      //   而「未过期」组只有 44% 在涨；字段里还出现 2024 年的日期。结论：它【不是当前周期结束日】，
      //   拿它判定会把「刚开始爬的新周期号」误标成周期到点。判定继续用原来的百分比启发式。
      //   采集链路（run.py periodEnd → console:period）保留，仅作数据留档，不参与任何判定。
      var reset=!!(a&&p&&a.rate===0&&p.rate!=null&&p.rate>=80&&(a.rpc30||0)>=(p.rpc30||0)*0.9);
      var st=(DATA.streak&&DATA.streak[pool]&&DATA.streak[pool][String(e.uid)])||0;
      rows.push({pool:pool,e:e,a:a,p:p,o:o,delta:delta,streak:st,reset:reset,
                 days:daysSince(e.added),sv:(e.pub?null:songVerdict(e,a))});
    });
  });
  return rows;
}
// 2026-10-25：标记判定抽成独立函数。① 行内渲染用；② 搜索框也能搜到「绑错歌」「共创」这类标签
// —— 售后直接搜关键词就能拉出全部同因名单，不用一个个翻。
function computeMarks(r, susSet){
  var e=r.e, a=r.a, sv=r.sv, hasSvc=!!sv, html='', txt=[];
  // 2026-11-01：公益号（pub=1）不参与 650 —— 自己的歌不进互听环、也没报名单任务，
  // C 组（任务周期）和 D 组（进度停滞）的标记对它全部无意义。hasSvc 正是这两组的统一闸门，
  // 让它为 true 就一次性跳过，不会在公益号上刷出一堆「无650任务 / 今日零增长」的假问题。
  var isPub=!!e.pub;
  if(isPub)hasSvc=true;
  function add(cls,label,tip){ html+='<span class="badge '+cls+'" title="'+esc(tip)+'">'+esc(label)+'</span>'; txt.push(label); }
  // A 歌曲问题
  if(sv)add(sv.cls,sv.txt,sv.tip);
  // B 账号状态
  if(susSet[String(e.uid)])add('b-yellow','待复核','登录已失效被判死，等下一轮确认后删号，需要号主换 CK');
  if(isPub)add('b-gray','公益号','公益号：只帮别人听歌，不占用别人的播放次数（自己登记的歌已从互听歌环剔除），也不参加签到/笔记。它没有 650 进度是正常的，不用查；要它回归普通号：编辑 → 账号类型选「普通号」');
  else if(!e.song)add('b-gray','公益号','没有登记歌曲的公益号：只帮别人听歌，没有 650 进度，属正常');
  if(!e.email)add('b-yellow','未绑邮箱','没填通知邮箱，号失效时通知不到人；不影响播放');
  if(e.noListen)add('b-gray','只收不听','号主自己关了互听：只收别人的播放，不给别人播');
  // 2026-11-11：按 acc_meta 细分根因（11-11 批量实时核查 12 个「无650任务」号的结论落进标记）——
  //   artist_id=''（acc_meta 已确认该号不是音乐人）→ 单独标「非音乐人」：拿普通用户号登记的歌，
  //   播放永远不会计入 650，找买家核实身份，不是让号主去后台点开通能解决的；
  //   artist_id 有值（音乐人身份在）→ 「无650任务」文案改为实习期/未开通口径：官方 90 天实习期
  //   转正前开不了特殊权益（实测实习号 maintainDays 恒 0），转正后开通进度才从 0 开始爬；
  //   acc_meta 没有该号记录 → 保持原通用文案（等元数据同步）。
  if(!isPub&&a&&a.rate==null&&e.song&&!(e.added&&e.added>=DATA.date)){
    var _am=DATA.artists?DATA.artists[String(e.uid)]:null;
    if(_am&&_am[0]==='')add('b-red','非音乐人','acc_meta 已确认该账号没有音乐人身份：拿普通用户号登记的歌，播放永远不会计入 650。不是号主去后台点开通能解决的 —— 找买家核实身份：要么换成音乐人号，要么按非音乐人号重新定价（11-11 实测 12 个无650任务号里 7 个是这类）');
    else if(_am&&_am[0])add('b-gray','无650任务','后台没返回 650 任务：该号音乐人身份已确认（'+(_am[1]||'音乐人')+'），但任务没开通 —— 多为实习期未转正（官方 90 天，实习期里特殊权益开不了，实测实习号维持天数恒为 0），转正后在音乐人后台开通，进度才从 0 开始爬；也可能卡在号主侧认证（有号超 90 天仍未转正）。用「号体检」工具实时复核 canOpen/状态确认根因');
    else add('b-gray','无650任务','后台没返回 650 任务：可能不是音乐人、没报名该任务或歌曲未过审，让号主去音乐人后台确认（账号元数据还没同步，用「号体检」工具实时复核可分辨是不是音乐人）');
  }
  // C 任务周期
  // 2026-10-25 补：入池 ≤2 天的新号即使 0% 也是正常爬坡（当天登记、次日才被听），
  // 不能按「周期已结束」报，否则新号全被误标成售后问题 → 新号前 1~2 天不打标记，只在顶部「今日入池」计数。
  // 另加 rpc30>=650 门槛：播放只有个位数/几十次时 0% 只是没人听，不是「播放不计数」。
  // 2026-10-26：周期归零（昨日≥80% 今日 0%）优先判定 —— 原来这种号会被下面 hasCycle 标成
  // 「有播放·650为0」，看起来像故障，实际是换新周期。文案与「较昨日」列的灰徽章保持一致。
  // 注：不动用 furtherVipGetTime（实测不是当前周期结束日，见 buildRows 处说明）。
  if(!hasSvc&&r.reset&&e.song)add('b-gray','周期归零','昨日 650 已到 '+(r.p&&r.p.rate!=null?r.p.rate+'%':'较高')+'、今天突然 0%：650 任务 31 天周期到点，新一期从 0 重新计（不管上期做没做满，没用完的百分比直接作废）。近30日播放量没塌，属正常，不用查');
  var hasCycle=false, isNewAcc=!(r.days==null||r.days>2);
  // 2026-10-26：这里原来写「(a.rate || 0) === 0」—— rate 为 null（后台没返回 650 任务）时
  // 0 也成立，于是「无650任务」的号被同时标成「有播放·650为0」，等于告诉号主
  // 「任务周期结束了去续期」，而它压根没有任务。改成必须真有 650 进度且为 0。
  // 注意：本函数整体位于 CONSOLE_HTML 模板字符串内，注释里不能出现反引号 —— 会提前结束模板。
  if(!hasSvc&&!r.reset&&!isNewAcc&&a&&a.rate!=null&&a.rate===0&&a.rpc30!=null&&a.rpc30>=650){
    hasCycle=true;
    // 2026-10-26：原来这里叫「0%卡住·查周期」，和顶部字段「有播放·650为0」是两个名字，
    // 顶部那个数字是两类之和，但搜索框搜「有播放」搜不到卡住的号 —— 用户上次抱怨过
    // 「顶上写的数字，搜索框里搜不到」正是这类问题。现在统一成同一个前缀，只加后缀区分
    // 严重程度：搜「有播放」两类全中，搜「卡住」只中连续 0% 的那批。
    // 2026-11-05：加实时复核（服务端 a.lr = 最近 30 分钟内直接查工作台的结果）。
    // 实测「0%」大半是快照采在网易结算之前：同一个号 07:20 快照 0%、11:30 实时已 100%。
    // 实时有进度 → 不报警，只挂个灰标说明数据已过期，连 D 组（零增长/未涨）也一起不打了。
    var lr=(a.lr!=null)?a.lr:null;
    if(lr!=null&&lr>0){
      add('b-gray','实时已恢复','快照里 650 是 0%，但刚才实时查工作台已经是 '+lr+'%：这一轮快照采在网易结算之前（结算窗口实测到 11:30~12:00），不是掉量也不是周期问题，不用管');
    }else{
      // lr===0 表示刚刚实时查过、确实还是 0%；lr===null 表示这次没查通（限流/超时），只能按快照说。
      var liveTxt=(lr===0?'实时复核（刚刚直接查工作台）仍是 0%。':'');
      if(r.streak>=2)add('b-orange','有播放·650为0·卡住','已连续 '+(r.streak+1)+' 天 0%，播放量却还在涨。'+liveTxt+'实测这类号绝大多数是快照采在网易结算之前（同号 07:20 快照 0%、11:30 实时 100%）。连续 8 天以上、实时也 0% 才是 650 任务本身不再统计播放 —— 音乐人后台没有「领取上期奖励 / 开启新一期」这种按钮（任务卡片只有「看攻略」，周期按 31 天自动换期），任务真被下掉的话只能重新报名或换号');
      else add('b-orange','有播放·650为0','近30日播放已有 650 次以上，但快照里的 650 进度是 0%。'+liveTxt+'多半是这一轮快照早于网易结算（结算窗口到 11:30~12:00），实时有进度就不会升成「·卡住」');
    }
  }
  // D 进度停滞
  // 2026-10-30：零增长拆成两类 —— rate 没动但 rpc30 在涨 = 播放已入账、网易分批结算还没滚到 650
  //（10-30 实测：10:10 早采出的 104 个零增长里 78 个近30日播放量在涨，纯属采集早于结算）；
  // rpc30 也平/跌才是真停滞。这样顶部「今日零增长」只统计真正要警惕的号，不再被结算延迟撑大。
  // cmpAt：悬浮提示带对比双方快照的采集时刻（北京时间），早采的对比一眼可辨。
  function cmpAt(a2,p2){var f=function(s){var m=/^([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2}):([0-9]{2})/.exec(String(s||''));if(!m)return '未知';var h=(+m[2]+8)%24;return (h<10?'0':'')+h+':'+m[3];};return '（对比快照采集时刻：今天 '+f(a2&&a2.at)+' vs 昨天 '+f(p2&&p2.at)+' 北京时间）';}
  // 2026-11-05 新增：近30日净增≤0（今天补的播放被 30 天前的老播放到期退出抵掉了）。
  // 用户口径：近30日播放量是 30 天滚动窗口 —— 今天补进去的播放可能正好被 30 天前那一波老播放退出抵消，
  // 看起来「总量没涨甚至略降」，但我们的播放确实补了。三条同时成立才标：
  //   ① 昨天→今天 rpc30 是 0 或负增长；② 650 进度也没涨（进度在涨就说明播放算数了，不用管）；
  //   ③ 两边快照采集时刻相差 ≤3 小时 —— 否则就是拿今天 07:00 的数和昨天 13:00 的数硬比，天生成负数
  //      （11-05 实测：不加第③条有 280 个号中招，加了只剩十几个）。
  function bjHour(s){var m=/^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2})/.exec(String(s||''));if(!m)return null;return ((+m[4]+8)%24)+(+m[5])/60;}
  function cmpOk(s1,s2,tol){var x=bjHour(s1),y=bjHour(s2);if(x==null||y==null)return false;var d=x-y;if(d<0)d=-d;return d<=tol||d>=24-tol;}
  var rpcD=(a&&r.p&&a.rpc30!=null&&r.p.rpc30!=null)?(a.rpc30-r.p.rpc30):null;
  // 2026-11-07：两周基准 —— (今天rpc30 - 14天前rpc30)/14 = 该号平均每天净涨次数（=「正常应增加」的
  // 观测水平，本身已含日常回吐，就是号主在列表里习惯看到的涨速）。回吐估算 = 平均日增 - 今日净变化，
  // 即今天补进去的播放里被 30 天前老播放到期退出抵掉的那部分。14 天前快照缺失（新号/断档）时不算数。
  var o14=r.o||null,avg14=null,back14=null;
  if(a&&o14&&a.rpc30!=null&&o14.rpc30!=null&&a.rpc30>o14.rpc30){
    avg14=Math.round((a.rpc30-o14.rpc30)/14);
    if(rpcD!=null)back14=avg14-rpcD;
  }
  var avg14Txt=(avg14!=null)?('该号近两周平均每天净涨约 '+avg14+' 次（=每天正常应增加的水平）'):'';
  var back14Txt=(back14!=null&&back14>0)?('，按这个水平估算今天有约 '+back14+' 次 30 天前的老播放到期退出、把新增抵掉'):'';
  // 只对「还没做满 100%」且「近30日播放量已经不是个位数」的号有意义：做满的号本来就不用管，
  // 播放量才几次的新号差个 ±2 也说明不了什么（不加这两条，11-05 会多出 7 个噪音行）。
  var netLoss=!!(!hasSvc&&!hasCycle&&!r.reset&&a&&r.p&&rpcD!=null&&rpcD<=0&&a.rate!=null&&r.p.rate!=null&&a.rate<100&&a.rate<=r.p.rate&&a.rpc30>=100&&cmpOk(a.at,r.p.at,3));
  if(netLoss)add('b-yellow','近30日净增≤0','近30日播放量今天没涨或略降（昨天 '+r.p.rpc30+' 次 → 今天 '+a.rpc30+' 次，差 '+(rpcD>0?'+':'')+rpcD+' 次），650 进度也没涨：这是 30 天滚动回吐 —— 今天补的播放被 30 天前的老播放到期退出抵掉了，不是播放没算进去、也不是没采集。'+(avg14!=null?avg14Txt+back14Txt+'。':'')+'常见于「30 天前刚好有一波高峰」的号（已满 100% 的、近30日播放才个位数的新号都不标）；连续 3 天以上净增≤0 才需要加播放量或换歌。'+cmpAt(a,r.p));
  if(!hasSvc&&!hasCycle&&a&&r.p&&a.rate!=null&&r.p.rate!=null&&a.rate<100&&a.rate-r.p.rate===0&&a.rpc30!=null&&r.p.rpc30!=null&&a.rpc30>r.p.rpc30)add('b-yellow','650未结算','650 进度和昨天一样，但近30日播放量在涨：播放已入账，网易分批结算还没滚到 650（入账窗口实测持续到 11:30~12:00）。停 1~2 天属正常节奏；连续 3 天以上播放量在涨而 650 不动才需要人工查。'+cmpAt(a,r.p));
  else if(!hasSvc&&!hasCycle&&!netLoss&&a&&r.p&&a.rate!=null&&r.p.rate!=null&&a.rate<100&&a.rate-r.p.rate===0)add('b-yellow','今日零增长','650 进度和昨天完全一样，且近30日播放量也没涨（=不多不少刚好持平）。这基本是 30 天滚动回吐，不是播放失效、也不是没采集'+(avg14!=null?('：'+avg14Txt+'，今天净变化 0，'+back14Txt.replace('，按这个水平估算','即')):'：每天补的播放被 30 天前同量的老播放到期退出抵掉')+'。播放量在跌的那种已单独标成「近30日净增≤0」；650 是后台分批结算，会停一两天再突然跳，先观察 2~3 天，连续 3 天以上零增长且实时复核仍是 0% 再人工查。'+cmpAt(a,r.p));
  if(!hasSvc&&!hasCycle&&!r.reset&&a&&a.rate!=null&&a.rate<100&&r.streak&&r.streak>=2)add('b-yellow','连续'+r.streak+'天未涨','连续 '+r.streak+' 天 650 进度没涨（含小幅回落，没快照的断档天已跳过）。先看「近30日播放量」：在跌=30天滚动窗口老播放退出（做过满 100% 的号常见，属自然衰减，不用管）；在涨却不动=播放被判无效，超过 4 天才需要人工查');
  // E 入池状态
  // 2026-10-26：给当天登记的号加行内标记，这样顶部「今日入池」这个数就能被搜索框直接筛出来（顶部=行内）。
  if(String(e.added||'').slice(0,10)===String(DATA.date))add('b-blue','今日入池','今天（'+DATA.date+'）才登记的新号：明天才进轮转开始被听，今天没有快照、650 进度是空的都属正常，不用查');
  if(!isPub&&e.song&&a&&(a.rate||0)>=100)add('b-green','已达100%','本周期 650 已达 100%：已经做满，不需要再刷更多（继续刷也不会有额外收益）。等下个 31 天周期重新起算会自动归零重爬');
  // 2026-10-26：删掉「次日才入池」「新号未开刷」两个标记 —— 新号前两三天进度低本来就是正常爬坡，
  // 打完标记反而制造噪音。顶部只保留一个「今日入池」总数（days<=0 的号数），行内不再重复提示。
  // F 数据
  // 2026-10-26：入池 ≤2 天的号本来就不该有快照（次日才开始被听、且新号往往还没开通任务），
  // 不能算「没采到」。原来判据是 days<=0，导致昨天登记、今天首次入池的号被误标「今日无快照」。
  // 另外「今日无快照」这个名字容易被读成「今天新入池的号」，改叫「采集缺失」，只表达数据没采到。
  if(!a&&e.song&&!(r.days!=null&&r.days<=2))add('b-gray','采集缺失','今天这一轮没采到该号快照（接口超时或号没跑），偶尔一次不用管；连续几天要查');
  return { html: html, text: txt.join(' ') };
}
// 2026-10-27 二次改：两列进度跟着日期范围换名字。跨度正好 1 天（就是原来「昨天→今天」）保持
// 原来的「昨日 / 今日 / 较昨日」；跨度大于 1 天改成「起始 / 结束 / 区间变化」——
// 否则拿 10-01 和 10-27 比还叫什么「较昨日」，标题就在撒谎。
// 2026-10-27 21:05：日期框改成筛入池日期后，650 两列固定「昨天 vs 今天」，名字不再变。
// 保留这个函数只为把真实日期写进表头 title（鼠标悬停能确认看的是哪两天）。
var LB_A='昨日650',LB_B='今日650',LB_D='较昨日';
// 2026-11-11：「歌手 / 音乐人」列的数据组装。mus = 该号音乐人昵称（acc_meta，artist_id='' 为已确认非音乐人）。
// 当晚简化：sns/hit（歌的歌手列表、同名比对）不再上屏 —— 共创人太多把行撑太高；保留计算只为搜索框命中（搜歌手名/音乐人名）。
function artistInfo(e){
  var am=(DATA.artists)?DATA.artists[String(e.uid)]:null;
  var sm=(e.song&&DATA.songs)?DATA.songs[String(e.song)]:null;
  var mus=(am&&am[0])?(am[1]||''):'';
  var sns='';
  if(sm){ if(sm.g){sns='查无此歌';} else {sns=(sm.ns&&sm.ns.length)?sm.ns.join(' / '):(sm.f||'');} }
  var hit=!!(mus&&sm&&sm.ns&&sm.ns.length&&('\u0001'+sm.ns.join('\u0001')+'\u0001').indexOf('\u0001'+mus+'\u0001')>=0);
  return { am:am, sm:sm, mus:mus, sns:sns, hit:hit };
}
function rangeLabels(){
  var a=(DATA&&DATA.prevDate)||'',b=(DATA&&DATA.date)||'';
  var thA=$('thA'),thB=$('thB'),thD=$('thD');
  if(thA){thA.title='昨日（'+(a||'')+'）快照里的 650 任务完成度（近30日有效播放，100%=已达标）';}
  if(thB){thB.title='今日（'+(b||'')+'）快照里的 650 任务完成度（近30日有效播放，100%=已达标）';}
  if(thD){thD.title=(a&&b?(a+' → '+b+'，'):'')+'今日650进度 - 昨日650进度；红色=涨，绿色=跌，0=今天没动，灰色「周期归零」=换新周期导致的 100→0（不是掉量）';}
  return true;
}
function render(){
  if(!DATA)return;
  var susSet={};(DATA.suspects||[]).forEach(function(s){susSet[String(s.uid)]=1;});
  renderRunbar();
  rangeLabels();                 // 必须在 buildRows 之前：行内 data-l 列名要用 LB_*
  var all=buildRows();
  all.forEach(function(r){var m=computeMarks(r,susSet);r.markHtml=m.html;r.markText=m.text;r.ai=artistInfo(r.e);});
  var q=($('q').value||'').trim().toLowerCase();
  // 2026-10-27 21:05：入池日期范围（纯前端过滤，不重新请求接口）。
  // added 形如 2026-10-27，截前 10 位后按字符串比大小（yyyy-mm-dd 正好可比）。
  var rg=drngOf(),rOn=!!(rg.from||rg.to);
  var drEl=$('dr');if(drEl)drEl.className='dr'+(rOn?' on':'');
  var baseRows=all.filter(function(r){
    if(POOLF!=='all'&&r.pool!==POOLF)return false;
    // 2026-10-27：客服 / 套餐 两个下拉筛选（顶部所有统计都跟着它变）
    if(AGENTF&&String(r.e.agent||'')!==AGENTF)return false;
    if(PLANF&&String(r.e.plan||'')!==PLANF)return false;
    // 入池日期范围：没登记入池日的老号，一旦启用这个筛选就不显示（它不落在任何区间内）
    if(rOn){
      var ad=String(r.e.added||'').slice(0,10);
      if(!ad)return false;
      if(rg.from&&ad<rg.from)return false;
      if(rg.to&&ad>rg.to)return false;
    }
    if(!q)return true;
    var e=r.e;
    // 2026-10-25：搜索也能命中标记文本（如搜「绑错歌」「共创」「未开刷」直接筛出同类号）
    // 2026-11-11：追加歌手名 / 音乐人昵称 —— 客服拿艺人名来核对时直接搜名字就能定位行
    return ((e.name||'')+' '+(e.email||'')+' '+(e.uid||'')+' '+(e.song||'')+' '+(e.agent||'')+' '+(e.plan||'')+' '+r.markText+' '+((r.ai&&r.ai.mus)||'')+' '+((r.ai&&r.ai.sns)||'')).toLowerCase().indexOf(q)>=0;
  });
  // 2026-11-05：统计卡筛选（点一下卡片 = 按这一项筛表格）。
  // 必须分两层：baseRows = 除统计卡以外的所有筛选，stats 的数字全部按 baseRows 算，
  // rows = baseRows 再叠 STATF，只喂表格。否则点完「今日上涨」后其它卡片全变 0，
  // 再点「今日下跌」就永远筛出空表，等于把按钮点废。
  function statHit(r,v){
    if(v==='__all')return true;
    if(v==='__data')return !!r.a;
    if(v==='__up')return r.delta!=null&&r.delta>0;
    if(v==='__down')return r.delta!=null&&r.delta<0&&!r.reset;
    // 连续 N 天未涨：N 从行内标记里取，≥3 天才算（和顶部数字同一口径）
    if(v==='__stuck3'){var mm=/连续([0-9]+)天未涨/.exec(r.markText||'');return !!mm&&+mm[1]>=3;}
    return (r.markText||'').indexOf(v)>=0;
  }
  var rows=STATF?baseRows.filter(function(r){return statHit(r,STATF);}):baseRows;
  var dnEl=$('dn');if(dnEl)dnEl.textContent=(rOn||STATF)?('筛出 '+rows.length+' 个'):'';
  var s=$('sort').value;
  if(s==='delta')rows.sort(function(x,y){return (y.delta==null?-999:y.delta)-(x.delta==null?-999:x.delta);});
  else if(s==='rate')rows.sort(function(x,y){return ((y.a&&y.a.rate)||-1)-((x.a&&x.a.rate)||-1);});
  var withData=baseRows.filter(function(r){return r.a;});
  // 2026-10-26：顶部只保留「看了要知道该不该动手」的字段。
  // 已删：平均650进度（一个池的均值没有行动意义）、次日才入池 / 新号未开刷（新号正常爬坡，行内也不打标记了）。
  // 新增：3天+未涨（真正需要人工的停滞号）、无650任务（刷多少都不会涨）、今日入池（当天新登记号数）。
  // 每个数字都来自行内标记文本，搜索框输入同一个词能拉到完全相同的行，不会再出现「顶部有数、搜不到」。
  var cntTxt=function(t){return baseRows.filter(function(r){return (r.markText||'').indexOf(t)>=0;}).length;};
  var ups=baseRows.filter(function(r){return r.delta!=null&&r.delta>0;}).length;
  var downs=baseRows.filter(function(r){return r.delta!=null&&r.delta<0&&!r.reset;}).length;
  var resets=cntTxt('周期归零');
  var zeroGrow=cntTxt('今日零增长');
  var unsettled=cntTxt('650未结算');
  // 2026-11-05：净增≤0（今天补的播放被 30 天前的老播放到期退出抵掉）与实时已恢复（快照 0% 但实时已涨）
  var netLoss=cntTxt('近30日净增≤0');
  var liveOk=cntTxt('实时已恢复');
  // 连续 N 天未涨：N 从行内「连续N天未涨」标记里取，≥3 天进这个数，≥7 天在 title 里单说。
  // 已满 100%、周期归零、歌曲有问题的号本来就不会有这个标记，所以不用再排除一次。
  var stuck3=0,stuck7=0;
  baseRows.forEach(function(r){var m=/连续([0-9]+)天未涨/.exec(r.markText||'');if(m){var n=+m[1];if(n>=3)stuck3++;if(n>=7)stuck7++;}});
  var noTask=cntTxt('无650任务');
  // 2026-11-11：非音乐人单独计数（acc_meta 确认 artist_id='' 的号，标记文本独立，不再混进无650任务）
  var noMus=cntTxt('非音乐人');
  // 「有播放·650为0」和它的升级版「有播放·650为0·卡住」现在是同一个前缀（2026-10-26 改名），
  // 一次 cntTxt 就两类全算，搜索框搜「有播放」也两类全中，数字和搜索结果终于对得上。
  var played0=cntTxt('有播放·650为0');
  var svcWrong=cntTxt('歌曲无效');
  var svcCoop=cntTxt('共创歌曲');
  // 今日入池 = 行内有「今日入池」标记的行数（added 日期就是今天）。
  // 直接比日期字符串，不经过 daysSince —— 那条路径依赖正则，模板字符串里踩过一次转义的坑。
  var newIn=cntTxt('今日入池');
  var done100=cntTxt('已达100%');
  // 2026-11-05：每张统计卡都是按钮 —— 点一下按这一项筛表格，再点一次取消（见 pickStat）。
  // data-sv 就是筛选值：__all/__data/__up/__down/__stuck3 是特殊口径，其余值直接当行内标记文本，
  // 和搜索框同一套匹配，所以不会再出现「卡上有数、点开筛不到」。
  var statCard=function(v,val,label,o){
    o=o||{};
    return '<div class="stat'+(o.warn?' warn':'')+(STATF===v?' on':'')+'" data-sv="'+v+'" title="'
      +(o.title?o.title+'。':'')+'点一下按「'+label+'」筛选表格，再点一次取消">'
      +'<b'+(o.color?' style="color:'+o.color+'"':'')+'>'+val+'</b><span>'+label+'</span></div>';
  };
  $('stats').innerHTML=
    statCard('__all',baseRows.length,'账号总数',{title:'当前筛选条件下的全部账号。点一下把池/客服/套餐/日期/搜索一起清掉'})
   +statCard('__data',withData.length,'今日有数据',{title:'今天这一轮快照采到了该号数据的号'})
   +statCard('__up',ups,'今日上涨',{color:'#c0392b',title:'650 进度比昨天高的号'})
   +statCard('__down',downs,'今日下跌',{color:'#1e8449',title:'650 进度比昨天低、且不是周期归零的号'})
   +statCard('今日入池',newIn,'今日入池',{color:'#255ea6',title:'added 日期就是今天的号：明天才进轮转开始被听，今天没有快照/进度是正常的。点「入池」列排序可以看各自登记日'})
   +statCard('周期归零',resets,'周期归零',{color:'#888',title:'昨日 650 已接近满、今天突然 0% 的号（31 天周期到点，不是掉量）'})
   +statCard('今日零增长',zeroGrow,'今日零增长',{warn:true,title:'650 进度和昨天完全一样，且近30日播放量也没涨（=不多不少刚好持平）'})
   +statCard('近30日净增≤0',netLoss,'净增≤0',{warn:true,title:'近30日播放量今天没涨或略降、650 进度也没涨：今天补的播放被 30 天前的老播放到期退出抵掉了（30 天滚动窗口的正常现象），不是播放没算进去。只统计两边快照采集时刻相差 3 小时以内的号，避免拿今早的数和昨晚的数硬比'})
   +statCard('650未结算',unsettled,'650未结算',{title:'650 进度没动但近30日播放量在涨：播放已入账，网易分批结算未滚到 650（入账窗口实测持续到 11:30~12:00），停 1~2 天属正常，不算真停滞'})
   +statCard('__stuck3',stuck3,'3天+未涨',{warn:true,title:'连续 ≥3 天 650 进度没涨（已排除已满 100%、周期归零、歌曲有问题的号）'+(stuck7?'，其中 ≥7 天 '+stuck7+' 个':'')+'。先看「近30日播放量」：在跌=30天滚动窗口老播放退出（做过满 100% 的号常见，属自然衰减）；在涨却不动=播放被判无效'})
   +statCard('无650任务',noTask,'无650任务',{warn:true,color:'#b85c00',title:'后台没返回 650 任务：多为实习期未转正（官方 90 天，实习期里特殊权益开不了），也可能是转正后没去开通 —— 用「号体检」工具实时复核根因。非音乐人的号单独算在「非音乐人」卡里，不重复计入这张'})
   +statCard('非音乐人',noMus,'非音乐人',{warn:true,color:'#a32d2d',title:'账号元数据已确认没有音乐人身份：拿普通用户号登记的歌，播放永远不会计入 650。找买家核实身份：换音乐人号或按非音乐人号重新定价'})
   +statCard('有播放·650为0',played0,'有播放·650为0',{warn:true,title:'近30日播放已有 650 次以上，但快照里的 650 进度是 0%：多半是这一轮快照采在网易结算之前（结算窗口到 11:30~12:00）。控制台会对这批号实时复核一次：实时有进度就不计入本数（改标「实时已恢复」'+(liveOk?'，本次 '+liveOk+' 个':'')+'），实时仍 0% 才计入。带「·卡住」后缀的是已连续 2 天以上 0%'})
   +statCard('歌曲无效',svcWrong,'歌曲无效',{warn:true,color:'#a32d2d',title:'歌曲无效 = 绑错歌（歌的作者里没有他）或 查无此歌（已下架/删除）：刷多少都不会涨，必须改绑'})
   +statCard('共创歌曲',svcCoop,'共创歌曲',{warn:true,color:'#b85c00',title:'共创歌曲 = 多人合唱：播放会被分摊给其他艺人，非主艺的号实测恒定 0%'})
   +statCard('已达100%',done100,'已达100%',{title:'本周期已做满 100% 的号：继续刷没有额外收益，等下个 31 天周期归零重爬'})
   ;
  // ===== 2026-10-27：套餐汇总 =====
  // 口径：按「登记时买的套餐」（accounts.plan）统计，不按剩余天数反推 —— exp 可改可续，反推会漂。
  // 三档来自服务端 reg_cfg，加档位不用改页面；存量号没套餐的单独算「未标注」，不混进任何一档。
  var planCnt={};
  rows.forEach(function(r){var k=String(r.e.plan||'');planCnt[k]=(planCnt[k]||0)+1;});
  var ph='';
  PLANS.forEach(function(p){
    var n=planCnt[p.label]||0;
    ph+='<div class="pl" data-plan="'+esc(p.label)+'" title="登记时买的是「'+esc(p.label)+'」的号：'+n+' 个（点这里可按套餐筛选）" style="cursor:pointer">'+esc(p.label)+'<b>'+n+'</b></div>';
  });
  // 配置里没有、但库里真有的历史套餐名（比如以前手输的），照样列出来，绝不吞数据
  Object.keys(planCnt).forEach(function(k){
    if(!k)return;
    if(PLANS.some(function(p){return p.label===k;}))return;
    ph+='<div class="pl muted" title="不在当前套餐档位里（历史数据），共 '+planCnt[k]+' 个">'+esc(k)+'<b>'+planCnt[k]+'</b></div>';
  });
  var noPlan=planCnt['']||0;
  if(noPlan)ph+='<div class="pl muted" title="登记时没有套餐信息的号（多半是加字段之前登记的老号）">未标注<b>'+noPlan+'</b></div>';
  $('plans').innerHTML=ph||'';
  // 套餐条点击 = 按该档筛选。用 data-plan + 事件委托，不写内联 onclick ——
  // 这段 JS 本身住在模板字符串里，内联写法要跨两层转义，10-27 就因为这个把整段脚本写崩过。
  $('plans').onclick=function(ev){
    var el=ev.target;
    while(el&&el!==this&&!(el.getAttribute&&el.getAttribute('data-plan')))el=el.parentNode;
    if(!el||el===this||!el.getAttribute)return;
    pickPlan(el.getAttribute('data-plan'));
  };
  // 2026-10-27：套餐和有效期是**两个字段**——套餐（plan）只用于统计口径，真正卡播放/互听时长的是有效期（exp）。
  // 手动改有效期不会自动改套餐，所以两边可能对不上（比如选了「1年」又把有效期改到 730 天）。
  // 这里只在渲染时标一个「≠」提示，不改任何数据、不拦任何操作。
  function planDaysOf(label){for(var i=0;i<PLANS.length;i++){if(PLANS[i].label===label)return PLANS[i].days;}return null;}
  function actualDaysOf(e){
    var x=String(e.exp||'').trim();
    if(!x||x==='forever'||x==='永久')return 0;                 // 0 = 永久
    var t1=Date.parse(x.slice(0,10)+'T00:00:00Z'),t2=Date.parse(String(e.added||'').slice(0,10)+'T00:00:00Z');
    if(isNaN(t1)||isNaN(t2))return null;
    return Math.round((t1-t2)/864e5);
  }
  var h='';
  rows.forEach(function(r,i){
    var e=r.e,a=r.a;
    var rateNow=a&&a.rate!=null?a.rate:'—',ratePrev=r.p&&r.p.rate!=null?r.p.rate:'—';
    var dCell=r.delta==null?'<span class="flat">—</span>':(r.reset?'<span class="badge b-gray" title="650 任务按 31 天一个周期结算：上一周期已结束、新周期从头计，所以今天变 0% 不是掉量（近30日播放量并没有塌）。不计入「今日下跌」，通常几天内会重新爬回">周期归零</span>':(r.delta>0?'<span class="up">+'+r.delta+'</span>':(r.delta<0?'<span class="down">'+r.delta+'</span>':'<span class="flat">0</span>')));
    var misCell=otherMis(a);
    // 2026-11-11：歌曲列不再带「公益」徽标 —— 实测它会把整列撑宽 ~37px（列宽按最宽行算，
    // 所有行的歌 ID 右边都跟着一大段空），且最右「标记」列已有完整的「公益号」徽标，属重复。
    var song=e.song?'<a class="song" target="_blank" href="https://music.163.com/song?id='+e.song+'">'+e.song+'</a>':'<span style="color:#bbb">公益</span>';
    var dur=(DATA.durs||{})[r.pool+'|'+e.uid]||(DATA.durs||{})[e.uid]||((a&&a.dur)||0);
    var durCell='<span class="flat">—</span>';
    if(dur>0){var mm=Math.floor(dur/60),ss=('0'+(dur%60)).slice(-2);
      durCell=dur<132?'<span class="badge b-red" title="短歌（不到 2:12）：10-22 时长 Bug 已修，现在短歌也能正常计入，这里只是提示">'+mm+':'+ss+'</span>'
        :(dur>336?'<span class="badge b-yellow" title="长歌（超过 5:36）：单次播放耗时长，会拖慢单班进度">'+mm+':'+ss+'</span>'
        :'<span class="num">'+mm+':'+ss+'</span>');}
    var marks=r.markHtml||'';   // 2026-10-25：标记已在 render 开头由 computeMarks 算好（搜索框也能命中）
    // 2026-10-27：客服 / 套餐两列；data-l 提供手机端卡片标签（列顺序变了标签不会跟着错）。
    var agCell=e.agent?'<span class="badge b-gray" title="这条登记是 '+esc(e.agent)+' 录的">'+esc(e.agent)+'</span>':'<span style="color:#ccc">—</span>';
    var plCell='';
    if(!e.plan){plCell='<span style="color:#ccc">未标注</span>';}
    else{
      plCell=esc(e.plan);
      var _pd=planDaysOf(e.plan),_ad=actualDaysOf(e);
      if(_pd!==null&&_ad!==null&&Math.abs(_ad-_pd)>10){
        plCell+='<span class="badge b-yellow" style="margin-left:4px" title="套餐记的是「'+esc(e.plan)+'」（'+(_pd?(_pd+' 天'):'永久')+'），但按入池日算有效期实际是 '+(_ad?(_ad+' 天'):'永久')+'。两个字段互相独立：套餐只影响统计口径，卡时长的是有效期；改一边不会自动改另一边。">≠</span>';
      }
    }
    // 2026-11-11（当晚简化）：只显示该号自己的音乐人昵称，一行、不换行。
    // 不再显示歌的歌手列表（共创人太多把行撑得很高）、不再显示 ✓/✗ 与「非音乐人/未同步」徽标
    // —— 非音乐人/绑错歌判定都在右侧「标记」列（按 artist id 判，比人眼核对名字可靠）。
    // artistInfo 仍保留：mus 喂给搜索框（搜音乐人名能命中行）。
    var ai=r.ai||artistInfo(e);
    var artCell=ai.mus
      ? '<span class="mus" title="'+esc(ai.mus)+'（音乐人昵称，uid '+esc(e.uid)+'）">'+esc(ai.mus)+'</span>'
      : '<span style="color:#bbb">—</span>';
    var opCell=(ROLE==='full')
      ? '<button class="mini" style="padding:4px 10px;font-size:12px" data-pool="'+r.pool+'" data-uid="'+esc(e.uid)+'" data-name="'+esc(e.name)+'">编辑</button>'
      : '<span style="color:#c9ced6;font-size:12px">只读</span>';
    // 2026-11-05：备注列 + 补号标签。
    // 「补」的意义在结账时才体现：这行是客户掉线后免费补的号，钱不算、客服也不提成。
    var noteCell='';
    if(e.rb)noteCell+='<span class="badge b-blue" title="补号：客户掉线后免费补的新号 —— 不计营收、不计客服提成；到期日继承原单（不重新给满套餐时间）">补</span>';
    if(e.note)noteCell+=(e.rb?' ':'')+'<span title="'+esc(e.note)+'">'+esc(String(e.note).slice(0,20))+(String(e.note).length>20?'…':'')+'</span>';
    if(!noteCell)noteCell='<span style="color:#bbb">—</span>';
    h+='<tr><td class="num">'+(i+1)+'</td>'
      +'<td><span class="badge '+(r.pool==='hz'?'b-hz">主群':'b-dz">定制')+'</span></td>'
      +'<td>'+esc(String(e.name||'').replace(/^qr:.+/,'扫码登录').replace(/^manual:/,'手动·'))+'</td>'
      +'<td>'+agCell+'</td>'
      +'<td class="num" data-l="UID">'+esc(e.uid)+'</td>'
      // 2026-11-02：新增邮箱列（数据来自 /api/console/data 的 entries[].email，dz 池走对穿同样带）
      +'<td class="mail" data-l="邮箱">'+(e.email?'<span class="eml" title="'+esc(e.email)+'（点选可整段复制）">'+esc(e.email)+'</span>':'<span style="color:#bbb">—</span>')+'</td>'
      +'<td class="num" data-l="歌曲">'+song+'</td>'
      +'<td data-l="歌手">'+artCell+'</td>'
      +'<td data-l="时长">'+durCell+'</td>'
      +'<td class="num" data-l="'+LB_A+'">'+ratePrev+'</td>'
      +'<td class="num" data-l="'+LB_B+'" style="font-weight:600">'+rateNow+(a&&a.at?'<div class="snap-at">采于 '+bjTime(a.at)+'</div>':'')+'</td>'
      +'<td data-l="'+LB_D+'">'+dCell+'</td>'
      +'<td class="num" data-l="近30日播放">'+(a&&a.rpc30!=null?a.rpc30:'—')+'</td>'
      +'<td data-l="笔记任务">'+misCell+'</td>'
      +'<td class="num" data-l="入池">'+fmtAdded(e.added)+'</td>'
      +'<td class="num" data-l="有效期">'+esc(e.exp||'永久')+'</td>'
      +'<td data-l="套餐">'+plCell+'</td>'
      +'<td data-l="备注">'+noteCell+'</td>'
      +'<td>'+(marks||'<span style="color:#bbb">正常</span>')+'</td>'
      +'<td>'+opCell+'</td></tr>';
  });
  $('tb').innerHTML=h||'<tr><td colspan="20" style="text-align:center;color:#999;padding:20px">没有匹配的账号</td></tr>';
}
// 点顶部的套餐卡片 = 直接按这个套餐筛选（再点一次取消）
function pickPlan(label){
  var el=$('fplan');
  if(!el)return;
  PLANF=(el.value===label)?'':label;
  el.value=PLANF;
  render();
}
// 2026-11-05：点顶部统计卡 = 按这一项筛选（再点一次取消）。
// '__all' 是「解除筛选」：把池/客服/套餐/入池日期/搜索一起清掉，回到全部号。
// 统计数字本身是按 baseRows 算的（不含 STATF），所以点卡片不会让其它卡片的数字跟着变。
function pickStat(v){
  if(!v)return;
  if(v==='__all'){
    STATF='';POOLF='all';AGENTF='';PLANF='';
    var qe=$('q');if(qe)qe.value='';
    var d1=$('date'),d2=$('dateTo');if(d1)d1.value='';if(d2)d2.value='';
    var fe=$('fagent');if(fe)fe.value='';
    var pe=$('fplan');if(pe)pe.value='';
    document.querySelectorAll('.tab').forEach(function(t){t.className='tab'+(t.getAttribute('data-p')==='all'?' on':'');});
    render();return;
  }
  STATF=(STATF===v)?'':v;
  render();
}
// 2026-10-23：运行状态横条（作业状态/应跑实跑/快照新鲜度/今日删号与待复核）
function fmtAdded(x){x=String(x||'');if(x.length<11)return esc(x);return esc(x.slice(0,10))+'<div class="snap-at">'+esc(x.slice(11))+'</div>';}
function bjTime(iso){if(!iso)return '';var d=new Date(iso);if(isNaN(d.getTime()))return '';var b=new Date(d.getTime()+8*3600*1000);return ('0'+(b.getUTCMonth()+1)).slice(-2)+'-'+('0'+b.getUTCDate()).slice(-2)+' '+('0'+b.getUTCHours()).slice(-2)+':'+('0'+b.getUTCMinutes()).slice(-2);}
/* 2026-11-10 晚：带年份的北京时间。D1 里的时间一律是 UTC ISO（regIso），
   以前链接列表/设备列表直接 slice + replace('T',' ') 截断 = 显示 UTC，比北京慢 8 小时。
   要知道具体哪天就只能用这个（bjTime 只给 月-日 时:分）。 */
function bjFull(iso){if(!iso)return '';var d=new Date(iso);if(isNaN(d.getTime()))return String(iso).slice(0,16).replace('T',' ');var b=new Date(d.getTime()+8*3600*1000);return b.getUTCFullYear()+'-'+('0'+(b.getUTCMonth()+1)).slice(-2)+'-'+('0'+b.getUTCDate()).slice(-2)+' '+('0'+b.getUTCHours()).slice(-2)+':'+('0'+b.getUTCMinutes()).slice(-2);}
function renderRunbar(){
  if(!DATA)return;
  var A=DATA.actions||[],C=DATA.coverage||{},F=DATA.fresh||{},D=DATA.dead||[],S=DATA.suspects||[];
  var h='';
  A.forEach(function(a){
    var label=a.pool==='hz'?'主群作业':'定制群作业';
    if(a.ok){
      // 2026-11-04：分出「进行中」这一档。以前只认 conclusion==='success'，在跑的那轮
      // conclusion 为空 → 要么显示成失败、要么根本不出现，进度看不见。
      var live=!!a.status&&a.status!=='completed';
      var jobTxt=a.jobs_total?(' · '+a.jobs_ok+'/'+a.jobs_total+' job'):'';
      var head;
      if(live){
        var dn=(a.jobs_done==null?a.jobs_ok:a.jobs_done);
        var tot=(a.jobs_total||0);
        head='<span style="color:#185FA5">● 进行中 '+(tot?(dn+'/'+tot+' job'):'（排队中）')+'</span>';
        if(a.jobs_ok&&dn>a.jobs_ok)head+='<span class="muted"> · 成功 '+a.jobs_ok+'</span>';
      }else if(a.conclusion==='success'){
        head='<span class="good">✓ 成功'+esc(jobTxt)+'</span>';
      }else{
        head='<span class="bad">✗ '+esc(a.conclusion||'失败')+esc(jobTxt)+'</span>';
      }
      // 2026-11-05：只读口令不显示「日志」入口。服务端已把 actions[].url 抹成空串，
      // 这里再按 ROLE 兜一层（缓存里的旧数据 / 将来字段改名时不至于漏出链接）。
      var logLink=((ROLE==='full')&&a.url)?' · <a href="'+esc(a.url)+'" target="_blank">日志</a>':'';
      h+='<div class="rb"><b>'+label+'</b> '+head+'<br>'
        +'<span class="muted">'+bjTime(a.created)+logLink+'</span></div>';
    }else{
      h+='<div class="rb"><b>'+label+'</b> <span class="muted">'+(a.note?esc(a.note):'未配置')+'</span></div>';
    }
  });
  var covH='';
  ['hz','dz'].forEach(function(p){
    var c=C[p];
    if(!c){covH+='<span class="muted">'+(p==='hz'?'主群':'定制群')+':无计划</span> ';return;}
    var mn=(c.missing_n==null?c.missing.length:c.missing_n);
    var cls=mn?'bad':'good';
    covH+='<span class="'+cls+'">'+(p==='hz'?'主群':'定制群')+' '+c.ran+'/'+c.expected+(mn?' 缺'+mn:'')+'</span> ';
  });
  h+='<div class="rb"><b>应跑/实跑</b><br>'+covH+'</div>';
  // 2026-11-09：今晚每号听几首（数据已在首屏响应里，0 额外请求）。
  // 口径：p = 每号本群歌单首数（已配平），另加 mixed_min~mixed_max 首热歌混听。
  var R=DATA.run;
  if(R){
    var accTxt=R.perDay?('加速档 '+R.perDay+' 首/天'+(R.days?(' · 入池 '+R.days+' 天'):'')):'';
    if(R.capped)accTxt='<span class="bad">加速档被稀释（'+R.perDay+' 首/天）</span>';
    h+='<div class="rb"><b>今晚听歌</b><br><span class="'+(R.capped?'bad':'muted')+'">每号约 '+R.p+' 首</span>'
      +'<div class="snap-at">'+accTxt+'</div>'
      +(R.max?'<div class="snap-at">最慢号 '+R.max+' 首</div>':'')+'</div>';
  }
  var fr='';
  ['hz','dz'].forEach(function(p){if(F[p])fr+='<span class="muted">'+(p==='hz'?'主群':'定制群')+' '+bjTime(F[p])+'</span> ';});
  h+='<div class="rb"><b>快照更新至</b><br>'+(fr||'<span class="muted">当日无快照</span>')+'</div>';
  // 2026-10-26：「当日删号」原来直接数 dead_log 里今天有几条，但删完又登记回来的号
  // （迁移到定制群、当天重登）也被算成删号，右上角就会一直挂着一个并不存在的「删了 1 个」。
  // 现在拿当日删除明细和当前号池做差集：uid 还在任一池里 = 已回池，不算删号。
  var liveUid={};
  (DATA.hz||[]).concat(DATA.dz||[]).forEach(function(e){if(e&&e.uid)liveUid[String(e.uid)]=1;});
  var dl=(DATA.deadToday||(function(){return D.filter(function(d){return (d.at||'').slice(0,10)===DATA.date;});})());
  var deadReal=0, deadBack=0;
  dl.forEach(function(x){ if(liveUid[String(x.uid)])deadBack++; else deadReal++; });
  h+='<div class="rb"><b>当日删号</b> <span class="'+(deadReal?'bad':'muted')+'">'+deadReal+'</span>'
    +(deadBack?' · <b>已回池</b> <span class="good">'+deadBack+'</span>':'')
    +' · <b>待复核</b> <span class="'+(S.length?'bad':'good')+'">'+S.length+'</span></div>';
  $('runbar').innerHTML=h;
  if(D.length||S.length){
    $('deadBox').hidden=false;
    var dh='';
    // 2026-10-26：「通知号主」列。cookie_invalid 是 run.py 当场发信，恒为已通知；
    // 手动删号要等 12 小时才判（迁移/重登不发），所以会先显示「待判」。
    function ntTxt(d){
      var st=d.notice;
      // 2026-10-26：老记录（没有 dead_notice 行）原来对 cookie_invalid 一律显示「已通知」，
      // 但这是「机制上应该发」而不是「查得到的已发」——10-23 那批手工调接口删的就没有 run.py
      // 在场，一封都没出去。改成描述触发方式，不断言送达。可在图例里看口径。
      if(!st){ return (d.reason||'')==='cookie_invalid'?'<span class="muted">自动判死·run.py 发信</span>':'<span class="muted">—</span>'; }
      if(st.state==='sent')return '<span class="good">已通知</span>';
      if(st.state==='claimed')return '<span class="muted">发送中</span>';
      if(st.state==='skip_returned')return '<span class="good">已回池·不发</span>';
      if(st.state==='skip_noemail')return '<span class="muted">无邮箱·不发</span>';
      // 过了判定窗口还在 pending ＝ 已经判过、发信失败被退回重试（notify_dead 的回执），
      // 这时候再写「待判·12h」会让人以为系统还没干活。
      // 2026-10-26 修复：removed_at 是 bjStamp() 生成的【北京时间】字符串，原来直接拼 'Z'
      // 当 UTC 解析，基准差 8 小时 → 「待判·12h」实际要到 21 小时才变「待发送·重试中」。
      // 带时区后缀的值原样解析，不带后缀的一律按 +08:00 解释。
      var rawT=String(st.removed_at||'');
      var t0=Date.parse(/[Zz]$|[+-][0-9]{2}:[0-9]{2}$/.test(rawT)?rawT:(rawT.replace(' ','T')+'+08:00'));
      if(!isNaN(t0)&&(Date.now()-t0)>13*3600000)return '<span class="muted">待发送·重试中</span>';
      return '<span class="muted">待判·12h</span>';
    }
    // 2026-10-26：原因列原来是 D1 内部英文码（manual / cookie_invalid / expired），
    // 对内看是「同一个词反复出现、看不出区别」，对外也看不懂。这里翻成中文并说清区别。
    function rsTxt(r){
      r=String(r||'');
      if(r==='manual')return '手动删除<span class="muted">·控制台</span>';
      if(r==='cookie_invalid')return 'Cookie失效<span class="muted">·自动判死</span>';
      if(r==='expired')return '到期清理<span class="muted">·自动</span>';
      // 2026-11-05：到期不再删号，改成降级为公益号（自己歌不听、仍帮别人听），号主续费即恢复
      if(r==='expired_pub')return '到期降公益<span class="muted">·未删号</span>';
      if(r==='unknown'||!r)return '<span class="muted">—</span>';
      return esc(r);
    }
    // 2026-10-26：10-23 那批清理脚本把 name 写成「manual:<uid>」了，D1 已就地修正，
    // 这里再兜一层，避免老数据或别处再传脏值。
    function nmTxt(n){ return esc(String(n||'').replace(/^qr:.+/,'扫码登录').replace(/^manual:/,'')); }
    D.slice(0,12).forEach(function(d){dh+='<tr><td>'+(d.pool==='hz'?'主群':'定制')+'</td><td class="num">'+esc(d.uid)+'</td><td>'+nmTxt(d.name)+'</td><td>'+rsTxt(d.reason)+'</td><td>'+ntTxt(d)+'</td><td class="num">'+esc((d.at||'').slice(5,16))+'</td></tr>';});
    S.slice(0,12).forEach(function(s){
      // 2026-11-04：已发过重登提醒的单独标出来 —— 这类号已摘出听众环、不再占应跑名额，
      // 状态是「等号主重新登记」，跟刚判出来还没通知的待复核不是一回事。
      var st=s.relogin
        ?('已通知重登 '+(s.relogin||'').slice(0,10)+'，等号主重新登记后自动恢复')
        :('待复核（suspect_at '+esc((s.since||'').slice(0,16))+'）');
      dh+='<tr><td>'+(s.pool==='hz'?'主群':'定制')+'</td><td class="num">'+esc(s.uid)+'</td><td>'+esc(s.name)+'</td><td colspan="3">'+esc(st)+'</td></tr>';
    });
    $('deadList').innerHTML='<table><thead><tr><th>池</th><th>UID</th><th>账号</th><th>原因</th><th>通知</th><th>时间</th></tr></thead><tbody>'+dh+'</tbody></table>';
  }
}
window.openEdit=function(pool,uid,name){
  $('eLink').value='';$('eEmail').value='';$('eExp').value='';$('eNo').value='';$('eCk').value='';$('em').textContent='';$('ePub').value='';
  // 2026-10-27：客服/套餐下拉每次打开都按当前配置重建（名单可能在别的标签页刚改过）
  applyCfg(DATA&&DATA.cfg);
  if($('eAgent'))$('eAgent').value='';
  if($('ePlan'))$('ePlan').value='';
  // 2026-11-05：回填备注 / 补号状态。找不到行就不提交备注（避免把已有备注误清空）。
  var ent=null,arr=(pool==='dz'?(DATA&&DATA.dz):(DATA&&DATA.hz))||[];
  for(var i=0;i<arr.length;i++){var x=arr[i];
    if((uid&&String(x.uid)===String(uid))||(name&&String(x.name)===String(name))){ent=x;break;}}
  NOTE_OK=!!ent;
  $('eNote').value=ent?(ent.note||''):'';
  $('eRb').value='';$('rbStart').value='';$('rbFrom').value='';$('rbQ').value='';$('rbList').innerHTML='';
  $('rbBox').hidden=true;
  $('rbHint').textContent='到期日 = 原单登记日 + 本单套餐天数。这样客户不会因为补号白得剩下的月份；想手工指定到期日，就填上面的「有效期」，以你填的为准。';
  $('rbNow').innerHTML=(ent&&ent.rb)
    ? ('当前：<span class="badge b-blue">补</span> 已标记为补号'+(ent.rbStart?'（原单登记日 '+esc(ent.rbStart)+'）':'')+' —— 这单不算营收、不算客服提成')
    : '当前：正常单（计入营收、算客服提成）';
  $('mTitle').textContent='编辑账号 · '+(pool==='hz'?'主群':'定制群');
  $('mSub').textContent=name+(uid?' / uid '+uid:'');
  $('modal').hidden=false;
  $('eSave').onclick=function(){doEdit(pool,{uid:uid,name:name},'update');};
  $('eDel').onclick=function(){if(confirm('确定从'+(pool==='hz'?'主群':'定制群')+'删除账号 '+(name||uid)+'？删除后不能恢复。12 小时内没有重新登记回来（含迁到另一群），系统会自动给号主发一封「账号信息过期」邮件。'))doEdit(pool,{uid:uid,name:name},'delete');};
};
// 补号：选「是补号」才展开原单查找区（不选就不动，避免误改已标记的号）
$('eRb').onchange=function(){$('rbBox').hidden=(this.value!=='1');};
// 按手机号 / 原 UID 查成交台账 —— 原号早就删了也能查到，这正是流水表存在的意义
$('rbFind').onclick=function(){
  var t=JSON.parse(TOKEN||'{}'),q=$('rbQ').value.replace(/[^0-9A-Za-z_:\\-]/g,'').trim();
  if(q.length<4){$('rbList').innerHTML='<span style="color:#a32d2d">至少输入 4 位（手机号 / UID）</span>';return;}
  $('rbList').innerHTML='<span style="color:#888">查询中…</span>';
  api('/api/console/findorder',{user:t.user,pass:t.pass,q:q}).then(function(o){
    if(!(o.ok&&o.d&&o.d.ok)){$('rbList').innerHTML='<span style="color:#a32d2d">'+esc((o.d&&o.d.message)||'查询失败')+'</span>';return;}
    var rs=o.d.rows||[];
    if(!rs.length){$('rbList').innerHTML='<span style="color:#888">没查到成交记录（可能是 11-02 之前就删掉的号，备份里也没捞到）。可以直接手填下面的原单登记日。</span>';return;}
    var hh='';
    for(var i=0;i<rs.length;i++){var r=rs[i];
      hh+='<div class="rbit" data-i="'+i+'" style="padding:6px 8px;border:1px solid #e6ebf1;border-radius:8px;margin-bottom:5px;cursor:pointer;background:#fff">'
        +'<b>'+esc(r.day)+'</b> · '+esc(r.name||'—')+' · '+esc(r.plan||'未标注')
        +(r.price!=null?(' · '+r.price+' 元'):' · <span style="color:#b06a00">待补价</span>')
        +(r.rb?' <span class="badge b-blue">补</span>':'')
        +(r.alive?' <span class="badge b-green">还在池里</span>':' <span class="badge b-gray">已删除</span>')
        +'<div style="color:#888;font-size:11.5px">uid '+esc(r.uid)+' · 到期 '+esc(r.exp||'永久')+' · '+(r.agent?esc(r.agent):'未标客服')+'</div></div>';
    }
    $('rbList').innerHTML=hh;
    var nodes=$('rbList').querySelectorAll('.rbit');
    for(var k=0;k<nodes.length;k++){
      nodes[k].onclick=function(){
        var r=rs[Number(this.getAttribute('data-i'))||0];
        if(!r)return;
        for(var z=0;z<nodes.length;z++)nodes[z].style.background='#fff';
        this.style.background='#eef6e6';
        $('rbStart').value=r.day||'';
        $('rbFrom').value=r.id||'';
        if(!$('eNote').value.trim())$('eNote').value='原单 '+r.day+' '+r.plan+(r.name?(' '+r.name):'')+' 掉线补登';
        if(!$('ePlan').value&&r.plan)$('ePlan').value=r.plan;
        var pl=null;
        for(var j=0;j<PLANS.length;j++){if(PLANS[j].label===r.plan)pl=PLANS[j];}
        if(pl&&pl.days){
          $('rbHint').textContent='按原单「'+r.plan+'」'+pl.days+' 天算：继承后到期日 = '+dAdd(r.day,pl.days)+'（点保存才生效）';
        }else if(pl){
          $('rbHint').textContent='原单是永久档 → 本单也按永久算（点保存才生效）';
        }else{
          $('rbHint').textContent='原单套餐没标注，算不出到期日：请在上面「有效期」里手工填一个，或先把套餐选成原单那档。';
        }
      };
    }
  }).catch(function(){$('rbList').innerHTML='<span style="color:#a32d2d">网络错误</span>';});
};
// 事件委托：表格内点「编辑」按钮（data-pool 属性路由到 openEdit），不受行重绘影响
$('tb').addEventListener('click',function(ev){
  var b=ev.target;
  while(b&&b!==this&&!(b.getAttribute&&b.getAttribute('data-pool')))b=b.parentNode;
  if(b&&b!==this&&b.getAttribute)openEdit(b.getAttribute('data-pool'),b.getAttribute('data-uid')||'',b.getAttribute('data-name')||'');
});
function doEdit(pool,e,action){
  var t=JSON.parse(TOKEN||'{}');
  var body={user:t.user,pass:t.pass,pool:pool,action:action,uid:e.uid,name:e.name};
  if(action==='update'){
    body.link=$('eLink').value.trim();body.email=$('eEmail').value.trim();body.exp=$('eExp').value.trim();body.ck=$('eCk').value.trim();
    if($('eNo').value!=='')body.noListen=$('eNo').value==='1';
    if($('ePub').value!=='')body.pub=$('ePub').value==='1';
    // 2026-10-27：留空=不改（与其它栏一致）
    if($('eAgent').value)body.agent=$('eAgent').value;
    if($('ePlan').value)body.plan=$('ePlan').value;
    // 2026-11-05：备注是「所见即所存」—— 回填到了就整值提交（清空输入框 = 清空备注）。
    // 没回填到该行数据时干脆不提交，避免把别人的备注误清空。
    if(NOTE_OK)body.note=$('eNote').value.trim();
    // 补号：只有主动选了才提交，默认「不修改」不会被误触发（否则每次改邮箱都会重算到期日）
    if($('eRb').value!==''){
      body.rb=($('eRb').value==='1');
      if(body.rb){
        body.rbStart=$('rbStart').value.trim();
        body.rbFrom=parseInt($('rbFrom').value||'0',10)||0;
      }
    }
  }
  $('eSave').disabled=true;$('eDel').disabled=true;
  api('/api/console/entry',body).then(function(o){
    $('eSave').disabled=false;$('eDel').disabled=false;
    if(o.ok&&o.d.ok){$('em').textContent=o.d.message||'已保存';$('em').className='msg ok';setTimeout(function(){$('modal').hidden=true;loadData();},900);}
    else{$('em').textContent=(o.d&&o.d.message)||'操作失败';$('em').className='msg err';}
  }).catch(function(){$('eSave').disabled=false;$('eDel').disabled=false;$('em').textContent='网络错误';$('em').className='msg err';});
}
$('eCancel').onclick=function(){$('modal').hidden=true;};
// ===== 2026-11-05：月度结算 =====
// 口径：按 ledger 成交流水的 day（登记日）分月。补号单 rb=1 单列，不计营收/提成。
// 只读口令看不到这个按钮（applyRole 会隐藏），服务端也会 403。
var LGDATA=null;
function lgMoney(v){return (Math.round((Number(v)||0)*100)/100).toFixed(2);}
// 2026-11-10：明细里的「登记类型」标签。补号优先（rb=1），其次看 src。
function lgKind(r){
  if(r.rb)return '<span class="badge b-blue" title="客户掉线后免费补回来的号：不收费、不给客服提成，有效期继承原单">补号</span>';
  if(String(r.src||'')==='renew')return '<span class="badge" style="background:#e8f0fb;color:#255ea6" title="号原本就在池里，客户又买了一次；有效期在原到期日基础上累加，给客服提成">续费</span>';
  if(r.gift)return '<span class="badge b-yellow">赠号</span>';
  return '<span style="color:#777">新登记</span>';
}
// 2026-11-05：汇总卡改成「等宽 + 固定三行（标题 / 数值 / 小字）」。
// 之前是 flex + min-width:118px，卡片宽度跟着文案走 —— 「C庆林 · 有效单（算提成）」这种长标题
// 把前几张撑宽，第 7 张直接被挤到第二排；标题一折行，数值也跟着往下掉，看着像错位。
// 现在由外面用 grid 固定列宽，卡内三行都 nowrap + ellipsis，所以永远一排、数值永远对齐。
function lgStat(lbl,val,warn,sub){
  return '<div style="background:'+(warn?'#fdf3e3':'#f2f7ea')+';border-radius:10px;padding:8px 10px;min-width:0">'
    +'<span style="display:block;font-size:11.5px;color:#777;line-height:1.25;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="'+esc(lbl)+'">'+lbl+'</span>'
    +'<b style="display:block;font-size:18px;line-height:1.45;color:'+(warn?'#b06a00':'#3b6d11')+';white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+val+'</b>'
    +'<span style="display:block;font-size:11px;line-height:1.3;color:'+(warn?'#b06a00':'#7c9866')+';opacity:.85;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+(sub||'&nbsp;')+'</span>'
    +'</div>';
}
function lgTable(firstCol,arr,withPrice){
  if(!arr||!arr.length)return '<p style="color:#999;margin:6px 0 12px">没有数据</p>';
  // 2026-11-05：三张表并排后每张只有 ~300px，「其中补号/其中赠号」这种长表头会把表格撑爆，
  // 改成「补号/赠号」并收窄字号与内边距；完整含义挂在 title 上。
  var TH='padding:5px 6px;background:#f5f6f8;color:#555;font-weight:600;white-space:nowrap;font-size:11.5px';
  var TD='padding:5px 6px;border-bottom:1px solid #f2f2f2;white-space:nowrap';
  var h='<table style="border-collapse:collapse;width:100%;font-size:12px;margin:0;table-layout:auto"><thead><tr>'
    +'<th style="text-align:left;'+TH+'">'+firstCol+'</th>'
    +(withPrice?'<th style="text-align:right;'+TH+'">单价</th>':'')
    +'<th style="text-align:right;'+TH+'">单数</th>'
    +'<th style="text-align:right;'+TH+'" title="其中补号：免费补偿的单，不算钱不提成">补号</th>'
    +'<th style="text-align:right;'+TH+'" title="其中赠号：公益赠号 / 手动加的号，不算单不提成">赠号</th>'
    +'<th style="text-align:right;'+TH+'">金额</th></tr></thead><tbody>';
  for(var i=0;i<arr.length;i++){
    var r=arr[i];
    h+='<tr><td style="'+TD+';max-width:110px;overflow:hidden;text-overflow:ellipsis" title="'+esc(r.k==null?'—':r.k)+'">'+esc(r.k==null?'—':r.k)+'</td>'
      +(withPrice?'<td style="'+TD+';text-align:right">'+(r.price>=0?r.price+' 元':'<span style="color:#b06a00">未定价</span>')+'</td>':'')
      +'<td style="'+TD+';text-align:right">'+r.cnt+'</td>'
      +'<td style="'+TD+';text-align:right;color:#255ea6">'+r.rbCnt+'</td>'
      +'<td style="'+TD+';text-align:right;color:#b06a00">'+(r.giftCnt||0)+'</td>'
      +'<td style="'+TD+';text-align:right;font-weight:600">'+lgMoney(r.money)+'</td></tr>';
  }
  return h+'</tbody></table>';
}
function lgRender(o){
  LGDATA=o;
  var t=o.total||{};
  // 客服下拉：选项来自服务端返回的全量分组（不受当前筛选影响），保留当前选择
  var agSel=$('lgAgent');
  if(agSel){
    var cur=agSel.value||o.agent||'';
    var arr=o.agents||[], opts='<option value="">全部客服</option>';
    for(var j=0;j<arr.length;j++){
      var a=arr[j].agent||'';
      opts+='<option value="'+(a?esc(a):'__none__')+'"'+((cur===(a||'__none__'))?' selected':'')+'>'+(a?esc(a):'(无客服)')+'（'+arr[j].cnt+'）</option>';
    }
    agSel.innerHTML=opts;
  }
  var who=o.agent?(o.agent==='__none__'?'（无客服）':o.agent):'';
  // 2026-11-05：固定 7 列网格（不再用 flex 自适应），7 张卡恒定一排；客服名不再并进卡标题
  // （它太长会把整行撑爆），当前筛选的是谁由下面那条绿底提示说明。
  // 口径顺序按「先看钱、再看提成、最后看构成」排：收入 → 有效单 → 成交 → 退单 → 补号/赠号/待补价。
  var h='<div style="display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:8px;margin-bottom:12px">'
    +lgStat('实际收入（元）',lgMoney(t.aliveMoney),false,'退单不计')
    +lgStat('有效单（算提成）',(t.valid||0),false,'已扣退单')
    +lgStat('成交单数',(t.cnt||0),false,(t.gone||0)>0?('含退单 '+t.gone+' 单'):'全部有效')
    +lgStat('退单·号已删',(t.gone||0),(t.gone||0)>0,lgMoney(t.goneMoney)+' 元')
    +lgStat('补号单',(t.rbCnt||0),false,'不算钱')
    +lgStat('赠号/手动号',(t.giftCnt||0),(t.giftCnt||0)>0,'不算单')
    +lgStat('待补价',(t.unpriced||0),(t.unpriced||0)>0,'套餐空着')
    +'</div>';
  /* 2026-11-10：登记类型结构条 —— 直接回答「续费的号号池不增加，怎么看出客服做了多少续费」。
     数据来自接口的 bySrc（新登记 new / 续费 renew / 补号 fix）。 */
  var S=o.bySrc||{}, sn=(S['new']||{}), sr=(S['renew']||{}), sf=(S['fix']||{}), so=(S['other']||{});
  h+='<div style="display:flex;gap:14px;flex-wrap:wrap;align-items:center;background:#f7f9fc;border:1px solid #e6ebf2;border-radius:9px;padding:7px 12px;margin:0 0 10px;font-size:12.5px">'
    +'<b style="color:#333">本月结构</b>'
    +'<span>新登记 <b style="color:#3b6d11">'+(sn.cnt||0)+'</b> 单 · '+lgMoney(sn.money||0)+' 元</span>'
    +'<span>续费 <b style="color:#255ea6">'+(sr.cnt||0)+'</b> 单 · '+lgMoney(sr.money||0)+' 元</span>'
    +'<span>补号 <b style="color:#b06a00">'+(sf.cnt||0)+'</b> 单 · 免费不计提成</span>'
    +((so.cnt||0)>0?'<span style="color:#888">历史回填 <b>'+(so.cnt||0)+'</b> 单</span>':'')
    +'<span style="color:#999;font-size:11.5px">「续费 / 补号」从 2026-11-10 起才打类型标记，之前的单分不出来</span></div>';
  if(who){
    h+='<p style="font-size:11.5px;color:#3b6d11;margin:0 0 8px;background:#f2f7ea;padding:5px 10px;border-radius:7px">'
      +'仅统计 <b>'+esc(who)+'</b> · '+esc(o.month)+' 的单（点「全部客服」看全群）</p>';
  }
  if(t.unpriced>0){
    h+='<p style="font-size:11.5px;color:#b06a00;margin:0 0 8px">有 '+t.unpriced+' 单没定价（历史回填时套餐空着，或档位配置里没填价格），这批<b>没算进合计</b>。'
      +'<button class="mini" id="lgFix" style="margin-left:8px;padding:3px 10px;font-size:11.5px">按当前配置价补齐</button></p>';
  }
  if((t.gone||0)>0){
    h+='<p style="font-size:11.5px;color:#777;margin:0 0 8px;line-height:1.6">「退单·号已删」= 成交后号被删了（掉线判死 / 手动删），共 '
      +(t.gone||0)+' 单 '+lgMoney(t.goneMoney)+' 元，这部分<b>不计收入、不计提成</b>。'
      +'成交 '+t.cnt+' 单 / 账面 '+lgMoney(t.money)+' 元，扣掉退单后：实际收入 <b>'+lgMoney(t.aliveMoney)+' 元</b>、有效单 <b>'+(t.valid||0)+'</b> 单。</p>';
  }
  // 2026-11-05：三张分组表改并排（原来一张一行，竖向占掉大半屏，害得整个弹窗要滚）。
  // 并排后高度只取决于最高的那张，弹窗外层不再出滚动条，只有下面的成交明细自己滚。
  h+='<div style="display:flex;gap:10px;align-items:flex-start;margin-top:10px">'
    +'<div style="flex:1;min-width:0"><h4 style="margin:0 0 6px;font-size:13px">按套餐</h4>'+lgTable('套餐',o.byPlan,true)+'</div>';
  if(!who)h+='<div style="flex:1;min-width:0"><h4 style="margin:0 0 6px;font-size:13px">按客服</h4>'+lgTable('客服',o.byAgent,false)+'</div>';
  if(!o.pool)h+='<div style="flex:1;min-width:0"><h4 style="margin:0 0 6px;font-size:13px">按群</h4>'+lgTable('群',o.byPool,false)+'</div>';
  h+='</div>';
  // 明细
  var rows=o.rows||[];
  h+='<details'+(rows.length<=80?' open':'')+' style="margin-top:2px">'
    +'<summary style="cursor:pointer;color:#3b6d11;font-size:13px;padding:4px 0">成交明细（'+rows.length+(rows.length>=1200?' 条，只显示前 1200':' 条')+'）</summary>';
  // 2026-11-05：表头改 sticky（滚长列表时列名不跟着跑）；列宽按内容收窄，账号/备注可省略号。
  var MH='padding:6px 8px;background:#f5f6f8;color:#555;font-weight:600;white-space:nowrap;position:sticky;top:0;z-index:2;border-bottom:1px solid #e6e8ec';
  var MD='padding:5px 8px;border-bottom:1px solid #f2f2f2;white-space:nowrap';
  h+='<div style="max-height:calc(92vh - 560px);min-height:170px;overflow:auto;margin-top:6px;border:1px solid #eef0f3;border-radius:8px">'
    +'<table style="border-collapse:separate;border-spacing:0;width:100%;font-size:12.5px"><thead><tr>'
    +'<th style="text-align:left;'+MH+'">类型</th>'
    +'<th style="text-align:left;'+MH+'">登记日</th>'
    +'<th style="text-align:left;'+MH+'">群</th>'
    +'<th style="text-align:left;'+MH+'">账号</th>'
    +'<th style="text-align:left;'+MH+'">客服</th>'
    +'<th style="text-align:left;'+MH+'">套餐</th>'
    +'<th style="text-align:right;'+MH+'">金额</th>'
    +'<th style="text-align:left;'+MH+'">备注</th></tr></thead><tbody>';
  for(var i=0;i<rows.length;i++){
    var r=rows[i];
    h+='<tr'+(r.rb?' style="background:#f7fafd"':'')+'>'
      +'<td style="'+MD+'">'+lgKind(r)+'</td>'
      +'<td style="'+MD+'">'+esc(r.day)+'</td>'
      +'<td style="'+MD+'">'+(r.pool==='hz'?'主群':'定制')+'</td>'
      +'<td style="'+MD+';max-width:200px;overflow:hidden;text-overflow:ellipsis" title="'+esc(r.name||r.uid)+'">'+esc(String(r.name||r.uid||'').replace(/^qr:.+/,'扫码登录').replace(/^manual:/,'手动·'))
        +(r.alive?'':' <span class="badge b-red" title="退单：成交后号被删了（掉线判死 / 手动删），不计收入、不计提成">退单</span>')
        +(r.gift?' <span class="badge b-yellow" title="公益赠号或手动加的号，不是客户买的，不算提成">赠号</span>':'')
      +'</td>'
      +'<td style="'+MD+'">'+esc(r.agent||'—')+'</td>'
      +'<td style="'+MD+'">'+esc(r.plan||'未标注')+'</td>'
      +'<td style="'+MD+';text-align:right">'+(r.rb?'<span class="badge b-blue">补</span> 0.00':(r.gift?'<span style="color:#999">赠号</span>':(r.price==null?'<span style="color:#b06a00">待补价</span>':lgMoney(r.price))))+'</td>'
      +'<td style="'+MD+';color:#777;max-width:220px;overflow:hidden;text-overflow:ellipsis" title="'+esc(r.remark||'')+'">'+esc(r.remark||'')+'</td></tr>';
  }
  h+='</tbody></table></div></details>';
  $('lgBody').innerHTML=h;
  if($('lgFix'))$('lgFix').onclick=function(){lgReprice();};
}
function lgLoad(){
  var t=JSON.parse(TOKEN||'{}');
  var m=$('lgMonth').value||'';
  if(!m){$('lgm').textContent='请先选月份';$('lgm').className='msg err';return;}
  $('lgm').textContent='查询中…';$('lgm').className='msg';
  $('lgGo').disabled=true;
  api('/api/console/ledger',{user:t.user,pass:t.pass,month:m,pool:$('lgPool').value,agent:($('lgAgent')?$('lgAgent').value:'')}).then(function(o){
    $('lgGo').disabled=false;
    if(!(o.ok&&o.d&&o.d.ok)){$('lgm').textContent=(o.d&&o.d.message)||'查询失败';$('lgm').className='msg err';$('lgBody').innerHTML='';return;}
    $('lgm').textContent='';$('lgm').className='msg';
    lgRender(o.d);
  }).catch(function(){$('lgGo').disabled=false;$('lgm').textContent='网络错误';$('lgm').className='msg err';});
}
function lgReprice(){
  var t=JSON.parse(TOKEN||'{}');
  var m=$('lgMonth').value||'';
  if(!confirm('把 '+m+' 里「没定价」的单子，按当前配置价补齐？只补空的，已经有价的一律不动。'))return;
  api('/api/console/ledger_reprice',{user:t.user,pass:t.pass,month:m}).then(function(o){
    $('lgm').textContent=(o.d&&o.d.message)||'';
    $('lgm').className=(o.ok&&o.d&&o.d.ok)?'msg ok':'msg err';
    if(o.ok&&o.d&&o.d.ok)lgLoad();
  }).catch(function(){$('lgm').textContent='网络错误';$('lgm').className='msg err';});
}
$('lgClose').onclick=function(){$('lgModal').hidden=true;};
$('lgGo').onclick=lgLoad;
$('lgMonth').onchange=lgLoad;
$('lgPool').onchange=lgLoad;
if($('lgAgent'))$('lgAgent').onchange=lgLoad;
$('lgCsv').onclick=function(){
  if(!LGDATA||!LGDATA.rows||!LGDATA.rows.length){$('lgm').textContent='还没有数据，先点查询';$('lgm').className='msg err';return;}
  var out=[['登记日','群','账号','UID','客服','套餐','金额','是否补号','是否退单','备注']];
  for(var i=0;i<LGDATA.rows.length;i++){var r=LGDATA.rows[i];
    out.push([r.day,r.pool==='hz'?'主群':'定制群',String(r.name||'').replace(/^qr:.+/,'扫码登录').replace(/^manual:/,'手动·'),r.uid,r.agent,r.plan,
      r.rb?'0':(r.gift?'赠号':(r.price==null?'':r.price)),r.rb?'补号':'',r.alive?'':'退单',r.remark]);}
  var csv='\\ufeff'+out.map(function(a){return a.map(function(v){return '"'+String(v==null?'':v).replace(/"/g,'""')+'"';}).join(',');}).join('\\r\\n');
  var a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
  a.download='结算_'+(LGDATA.month||'')+'_'+(LGDATA.pool||'全部')+'_'+(LGDATA.agent?(LGDATA.agent==='__none__'?'无客服':LGDATA.agent):'全部客服')+'.csv';
  document.body.appendChild(a);a.click();document.body.removeChild(a);
};
$('btnLedger').onclick=function(){
  // 默认查「上个月」—— 结算是次月 15 号回头算上月，打开就是最常见的那一屏
  if(!$('lgMonth').value){
    var d=new Date(Date.now()+8*3600*1000);
    var p=new Date(Date.UTC(d.getUTCFullYear(),d.getUTCMonth()-1,1));
    $('lgMonth').value=p.toISOString().slice(0,7);
  }
  $('lgm').textContent='';$('lgBody').innerHTML='';
  $('lgModal').hidden=false;
  lgLoad();
};

// ===== 2026-10-27：客服名单 / 套餐档位维护（只读口令看不到这个按钮，服务端也会拦）=====
// 客服一行一个；套餐一行一个「显示名=天数」，天数 0 = 永久。改完保存，APK/EXE 下次登记自动拿到。
// 2026-11-06：新增「客服改名」——名单框只负责增删和排序，改名必须走上面的专用入口，
//   否则历史号 / 结算账本会停在旧名字（原因见 worker 里 /api/console/agent_rename 的注释）。
function buildRenameSel(){
  var c=(DATA&&DATA.cfg)||{agents:[]};
  var s=$('rnOld');if(!s)return;
  var cur=s.value||'';
  s.innerHTML='';
  var g0=document.createElement('option');g0.value='';g0.textContent='— 选择要改的客服 —';s.appendChild(g0);
  (c.agents||[]).forEach(function(a){
    var o=document.createElement('option');o.value=a;o.textContent=a;s.appendChild(o);
  });
  if(cur&&(c.agents||[]).indexOf(cur)>=0)s.value=cur;
}
// 保存名单前先看一眼：一边少人一边多人，很可能是在框里直接改了字
function suspectRename(oldList,newList){
  var gone=(oldList||[]).filter(function(a){return (newList||[]).indexOf(a)<0;});
  var add=(newList||[]).filter(function(a){return (oldList||[]).indexOf(a)<0;});
  if(!gone.length||gone.length!==add.length)return null;
  return {gone:gone,add:add};
}
/* ===== 2026-11-10：设备授权（客服电脑）===== */
/* 2026-11-10 晚：ctime 是 UTC ISO，这里原来是原样截断（显示 UTC，慢 8 小时），改走 bjFull。 */
function dvFmt(t){return t?esc(bjFull(t)):'-';}
function dvTxt(s){return s==='ok'?'已授权':(s==='hold'?'已停用':'待授权');}
function dvBadge(s){
  var c=s==='ok'?'#2e7d32':(s==='hold'?'#8a8a8a':'#b26a00');
  var b=s==='ok'?'#e8f5e9':(s==='hold'?'#f0f0f0':'#fff4e0');
  return '<span style="padding:1px 7px;border-radius:9px;background:'+b+';color:'+c+';font-size:11.5px;white-space:nowrap">'+dvTxt(s)+'</span>';
}
function dvRender(rows){
  var h='<table style="width:100%;border-collapse:collapse;font-size:12.5px">'
    +'<tr style="background:#faf7f2;text-align:left">'
    +'<th style="padding:7px 6px">机器码</th><th>客服</th><th>每日上限</th><th>状态</th>'
    +'<th>首次出现</th><th>最近生成</th><th style="text-align:right">操作</th></tr>';
  if(!(rows||[]).length){
    h+='<tr><td colspan="7" style="padding:16px;color:#999;text-align:center">还没有任何设备。新版客服软件第一次生成链接后，这里就会出现。</td></tr>';
  }
  (rows||[]).forEach(function(r){
    var dev=esc(r.dev||'');
    var ag=esc(r.agent||'');
    var qt=(Number(r.quota)||200);
    h+='<tr style="border-top:1px solid #f0eae2">'
      +'<td style="padding:6px;font-family:ui-monospace,Consolas,monospace;white-space:nowrap">'+dev+'</td>'
      +'<td style="padding:0 6px">'+(ag||'-')+'</td>'
      +'<td style="padding:0 6px">'+qt+'</td>'
      +'<td style="padding:0 6px">'+dvBadge(String(r.state||'pending'))+'</td>'
      +'<td style="padding:0 6px;white-space:nowrap">'+dvFmt(r.ctime)+'</td>'
      +'<td style="padding:0 6px;white-space:nowrap">'+dvFmt(r.last_at)+'</td>'
      +'<td style="text-align:right;white-space:nowrap;padding:4px 2px">'
      +'<button class="mini" data-dv="ok" data-code="'+dev+'" data-agent="'+ag+'" data-quota="'+qt+'" style="margin:0 2px;padding:4px 8px">授权</button>'
      +'<button class="mini gray" data-dv="hold" data-code="'+dev+'" data-agent="'+ag+'" data-quota="'+qt+'" style="margin:0 2px;padding:4px 8px">停用</button>'
      +'<button class="mini gray" data-dv="del" data-code="'+dev+'" style="margin:0 2px;padding:4px 8px">删除</button>'
      +'</td></tr>';
  });
  h+='</table>';
  $('dvBody').innerHTML=h;
}
function dvLoad(){
  var t=JSON.parse(TOKEN||'{}');
  $('dvm').textContent='读取中…';$('dvm').className='msg';
  api('/api/console/dev_list',{user:t.user,pass:t.pass}).then(function(r){
    if(r.ok&&r.d&&r.d.ok){
      dvRender(r.d.rows||[]);
      $('dvm').textContent='共 '+(r.d.rows||[]).length+' 台设备（最多显示 300 台）';
      $('dvm').className='msg ok';
    }else{
      $('dvm').textContent=(r.d&&r.d.message)||'读取失败';$('dvm').className='msg err';
    }
  }).catch(function(){$('dvm').textContent='网络错误，请重试';$('dvm').className='msg err';});
}
$('btnDev').onclick=function(){
  var c=(DATA&&DATA.cfg)||{agents:[]};
  $('dvAgent').innerHTML=(c.agents||[]).map(function(a){return '<option>'+esc(a)+'</option>';}).join('');
  $('dvCode').value='';$('dvQuota').value='200';
  $('dvm').textContent='';$('dvm').className='msg';
  $('devModal').hidden=false;
  dvLoad();
};
$('dvClose').onclick=function(){$('devModal').hidden=true;};
$('dvReload').onclick=dvLoad;
$('dvAdd').onclick=function(){
  var t=JSON.parse(TOKEN||'{}');
  var dev=($('dvCode').value||'').replace(/[^0-9A-Za-z]/g,'').toUpperCase();
  if(dev.length<6){$('dvm').textContent='机器码长度不对（应该是客服软件里显示的那串字母数字）';$('dvm').className='msg err';return;}
  $('dvAdd').disabled=true;$('dvm').textContent='保存中…';$('dvm').className='msg';
  api('/api/console/dev_save',{user:t.user,pass:t.pass,dev:dev,agent:$('dvAgent').value||'',
    quota:parseInt($('dvQuota').value,10)||200,state:'ok'}).then(function(r){
    $('dvAdd').disabled=false;
    if(r.ok&&r.d&&r.d.ok){
      $('dvm').textContent=r.d.message||'已保存';$('dvm').className='msg ok';
      $('dvCode').value='';dvLoad();
    }else{
      $('dvm').textContent=(r.d&&r.d.message)||'保存失败';$('dvm').className='msg err';
    }
  }).catch(function(){$('dvAdd').disabled=false;$('dvm').textContent='网络错误，请重试';$('dvm').className='msg err';});
};
$('dvBody').addEventListener('click',function(ev){
  var el=ev.target;
  while(el&&el!==$('dvBody')&&!(el.getAttribute&&el.getAttribute('data-dv')))el=el.parentNode;
  if(!el||el===$('dvBody')||!el.getAttribute)return;
  var act=el.getAttribute('data-dv'),code=el.getAttribute('data-code');
  if(!code)return;
  if(act==='del'&&!confirm('删除设备 '+code+' ？\\n\\n删除后这台电脑下次生成链接会重新变成「待授权」，24 小时后又会被拦住。'))return;
  if(act==='hold'&&!confirm('停用设备 '+code+' ？\\n\\n停用后这台电脑立刻不能生成链接（记录保留，随时可以再授权）。'))return;
  var t=JSON.parse(TOKEN||'{}');
  $('dvm').textContent='处理中…';$('dvm').className='msg';
  var body={user:t.user,pass:t.pass,dev:code};
  var url='/api/console/dev_save';
  if(act==='del'){url='/api/console/dev_del';}
  else{body.state=act;body.agent=el.getAttribute('data-agent')||'';body.quota=parseInt(el.getAttribute('data-quota'),10)||200;}
  api(url,body).then(function(r){
    if(r.ok&&r.d&&r.d.ok){
      $('dvm').textContent=r.d.message||'完成';$('dvm').className='msg ok';dvLoad();
    }else{
      $('dvm').textContent=(r.d&&r.d.message)||'操作失败';$('dvm').className='msg err';
    }
  }).catch(function(){$('dvm').textContent='网络错误，请重试';$('dvm').className='msg err';});
});
/* ===== 2026-11-10：登记链接（新登记 / 续费 / 补登） =====
   为什么要在发链接时就选类型：客户提交那一刻，「号不在池 + 原单没到期」既可能是
   免费补登，也可能是付了钱的续费。系统分不出来，猜错一边就是白送套餐或客户白付钱。 */
var RG_REF = null;
function rgTok(){ return JSON.parse(TOKEN||'{}'); }
function rgKind(){ return $('rgKind').value||'new'; }
function rgKindName(k){ return k==='fix'?'补登':(k==='renew'?'续费':'新登记'); }
function rgSync(){
  var k=rgKind();
  $('rgRefBox').hidden=(k==='new');
  /* 2026-11-10：补登不需要选套餐 —— 有效期完全继承原单，选了也不生效。
     禁用而不是隐藏，让人看得见「这里本来有套餐、补登用不上」。 */
  $('rgPlan').disabled=(k==='fix');
  $('rgPlanTip').hidden=(k!=='fix');
}
$('rgKind').onchange=function(){ RG_REF=null; $('rgRefOut').innerHTML=''; rgSync(); };
/* 2026-11-10：按状态看链接（尤其「已过期」）。过期链接仍然是 unused，作废按钮照样给。 */
$('rgState').onchange=function(){ rgLoad(); };
$('btnReg').onclick=function(){
  var c=(DATA&&DATA.cfg)||{agents:[],plans:[]};
  $('rgAgent').innerHTML=(c.agents||[]).map(function(a){return '<option>'+esc(a)+'</option>';}).join('');
  $('rgPlan').innerHTML=(c.plans||[]).map(function(p){return '<option value="'+esc(p.key)+'">'+esc(p.label)+'</option>';}).join('');
  $('rgNote').value=''; $('rgm').textContent=''; $('rgm').className='msg';
  $('rgOut').innerHTML=''; $('rgRef').value=''; $('rgRefOut').innerHTML='';
  RG_REF=null; rgSync(); $('rgModal').hidden=false; rgLoad();
};
$('rgClose').onclick=function(){ $('rgModal').hidden=true; };
$('rgFind').onclick=function(){
  var t=rgTok(), q=($('rgRef').value||'').replace(/[^0-9A-Za-z_-]/g,'');
  if(q.length<4){ $('rgm').textContent='至少输 4 位（手机号 或 网易 UID）'; $('rgm').className='msg err'; return; }
  $('rgFind').disabled=true; $('rgm').textContent='搜索中…'; $('rgm').className='msg';
  api('/api/console/findorder',{user:t.user,pass:t.pass,q:q}).then(function(r){
    $('rgFind').disabled=false;
    if(!(r.ok&&r.d&&r.d.ok)){ $('rgm').textContent=(r.d&&r.d.message)||'搜索失败'; $('rgm').className='msg err'; return; }
    var rows=(r.d.rows||[]).filter(function(x){return !!x.exp;});
    if(!rows.length){
      $('rgRefOut').innerHTML='<div style="color:#b06a00;font-size:12px">没找到有到期日的原单。真没买过的客户请按「新登记」发链接。</div>';
      return;
    }
    var h='<div style="font-size:12px;color:#666;margin-bottom:5px">点一行选中它当原单：</div>';
    rows.forEach(function(x,i){
      h+='<div class="rghit" data-i="'+i+'" style="cursor:pointer;padding:7px 9px;border:1px solid #e3e8f0;border-radius:7px;margin-bottom:5px;font-size:12px;line-height:1.7">'
        +'<b>'+esc(x.name||'(无手机号)')+'</b> · uid '+esc(x.uid||'-')+' · '+esc(x.plan||'?')
        +' · 到期 <b>'+esc(x.exp||'')+'</b>'
        +' · 登记日 '+esc(String(x.start||x.day||'').slice(0,10))
        +(x.alive?' <span class="badge b-green">还在池</span>':' <span class="badge b-gray">号已删</span>')
        +(x.rb?' <span class="badge b-orange">补</span>':'')
        +'</div>';
    });
    $('rgRefOut').innerHTML=h;
    Array.prototype.forEach.call($('rgRefOut').querySelectorAll('.rghit'),function(el){
      el.onclick=function(){
        var x=rows[parseInt(el.dataset.i,10)]||{};
        RG_REF={ref:String(x.uid||x.name||''),exp:String(x.exp||''),name:x.name||'',alive:!!x.alive};
        Array.prototype.forEach.call($('rgRefOut').querySelectorAll('.rghit'),function(e2){e2.style.background='';e2.style.borderColor='#e3e8f0';});
        el.style.background='#eef6ff'; el.style.borderColor='#9cc4f5';
        $('rgm').textContent='已选原单：'+((x.name||x.uid||'')+'，到期 '+x.exp+(x.alive?'（这个号还在池里没掉线）':'')); $('rgm').className='msg ok';
      };
    });
  }).catch(function(){ $('rgFind').disabled=false; $('rgm').textContent='网络错误，请重试'; $('rgm').className='msg err'; });
};
$('rgGo').onclick=function(){
  var t=rgTok(), k=rgKind();
  if(k!=='new'&&!RG_REF){ $('rgm').textContent='先搜原单、点一行选中它，再生成'; $('rgm').className='msg err'; return; }
  if(k==='fix'&&RG_REF&&RG_REF.alive){ $('rgm').textContent='这个号还在号池里没掉线，不用补登（要延期请用「续费」）'; $('rgm').className='msg err'; return; }
  var body={user:t.user,pass:t.pass,kind:k,agent:$('rgAgent').value||'',
    plan:(k==='fix'?'':($('rgPlan').value||'')),hours:parseInt($('rgHours').value,10)||24,
    note:$('rgNote').value||''};
  if(k!=='new'){ body.fix_ref=RG_REF.ref; body.fix_exp=RG_REF.exp; }
  $('rgGo').disabled=true; $('rgm').textContent='生成中…'; $('rgm').className='msg';
  api('/api/regtoken_new',body).then(function(r){
    $('rgGo').disabled=false;
    if(!(r.ok&&r.d&&r.d.ok)){ $('rgm').textContent=(r.d&&r.d.message)||'生成失败'; $('rgm').className='msg err'; return; }
    var d=r.d;
    $('rgm').textContent='已生成（'+rgKindName(k)+'）'; $('rgm').className='msg ok';
    $('rgOut').innerHTML='<div style="margin-top:8px;padding:10px 12px;background:#f2fbf4;border:1px solid #cfe8d6;border-radius:9px;font-size:12.5px;line-height:1.95">'
      +'链接：<input readonly value="'+esc(d.link||'')+'" style="width:auto;min-width:400px;font-family:ui-monospace,Consolas,monospace" onclick="this.select()">'
      +'<br>有效期至 '+esc(bjFull(d.exp_at))+'（'+(d.hours||24)+' 小时），一条链接只能用一次'
      +(d.fix_exp?('<br>原单到期日：<b>'+esc(d.fix_exp)+'</b>'+(k==='fix'?'（补登后仍到这天，不延长）':'（续费在此基础上累加）')):'')
      +'<br><span style="color:#888">把链接发给客户，客户自己扫码登记，不用他给你密码。</span></div>';
    rgLoad();
  }).catch(function(){ $('rgGo').disabled=false; $('rgm').textContent='网络错误，请重试'; $('rgm').className='msg err'; });
};
function rgCp(url){
  /* 点编码复制整条链接；剪贴板 API 只在 https 下有，失败就弹框让用户手动复制 */
  if(navigator.clipboard&&navigator.clipboard.writeText){ navigator.clipboard.writeText(url); }
  else{ window.prompt('完整链接（手动复制）：', url); }
}
function rgLoad(){
  var t=rgTok();
  var stv=($('rgState')&&$('rgState').value)||'';
  var qv=(($('rgQ')&&$('rgQ').value)||'').trim();
  /* 2026-11-11：查询时忽略状态筛选（与 EXE 同口径）——不然状态框停在「已使用」，
     查一条还没用的链接会被滤掉，让人误以为客户没登记。 */
  var body={user:t.user,pass:t.pass,limit:((qv||stv)?80:25)};
  if(qv){ body.q=qv; } else if(stv){ body.state=stv; }
  $('rgList').innerHTML='<div style="color:#999;font-size:12px;padding:6px 0">读取中…</div>';
  api('/api/regtoken_list',body).then(function(r){
    if(!(r.ok&&r.d&&r.d.ok)){ $('rgList').innerHTML='<div style="color:#b06a00;font-size:12px">读取失败：'+esc((r.d&&r.d.message)||'')+'</div>'; return; }
    var rows=r.d.rows||[];
    if(!rows.length){ $('rgList').innerHTML='<div style="color:#999;font-size:12px">'+(qv?'没查到。换客户手机号、或把整条链接粘进来再试（只填 8 位编码也行）。':(stv?'这个状态下没有链接。':'还没有生成过链接。'))+'</div>'; return; }
    var h='<div class="twrap" style="max-height:250px;overflow:auto"><table style="font-size:12px"><thead><tr><th>类型</th><th>客服</th><th>套餐</th><th>状态</th><th title="点一下复制完整链接">编码</th><th>买家</th><th>生成时间</th><th>登记时间</th><th>备注</th><th>操作</th></tr></thead><tbody>';
    rows.forEach(function(x){
      var st=String(x.state||'unused');
      var stn=st==='unused'?'未使用':(st==='used'?'已使用':(st==='void'?'已作废':(st==='expired'?'已过期':'—')));
      var kn=String(x.kind||'new');
      /* 补登/续费的实际有效期来自原单，不来自套餐 —— 直接写原单到期日，
         比在套餐列里显示一个空值有用。 */
      var pl=(kn!=='new'&&x.fix_exp)?('原单到 '+esc(x.fix_exp)):esc(x.plan||'—');
      var code=esc(x.token||'');
      var link=location.origin+'/r/'+code;
      h+='<tr><td>'+rgKindName(kn)+'</td><td>'+esc(x.agent||'')+'</td><td>'+pl+'</td>'
        +'<td>'+(st==='unused'?'<b>'+stn+'</b>':('expired'===st?'<span style="color:#b06a00">'+stn+'</span>':stn))+'</td>'
        +'<td><span data-cp="'+link+'" title="点击复制完整链接" style="cursor:pointer;font-family:ui-monospace,Consolas,monospace;color:#3b6d11;text-decoration:underline dotted">'+code+'</span></td>'
        +'<td>'+esc(x.phone||x.uname||'—')+'</td>'
        +'<td>'+esc(bjTime(x.ctime))+'</td>'
        +'<td>'+(x.used_at?esc(bjTime(x.used_at)):'—')+'</td>'
        +'<td>'+esc(x.note||'')+'</td>'
        +'<td>'+((st==='unused'||st==='expired')?('<button class="mini gray" data-void="'+esc(x.token||'')+'">作废</button>'):'—')+'</td></tr>';
    });
    h+='</tbody></table></div>';
    if(qv){ h='<div style="font-size:11.5px;color:#666;margin:0 0 5px">查询「'+esc(qv)+'」：'+rows.length+' 条（点「显示全部」回最近列表）</div>'+h; }
    $('rgList').innerHTML=h;
    Array.prototype.forEach.call($('rgList').querySelectorAll('[data-cp]'),function(el){
      el.onclick=function(){ rgCp(el.getAttribute('data-cp')); };
    });
    Array.prototype.forEach.call($('rgList').querySelectorAll('[data-void]'),function(b){
      b.onclick=function(){
        var code=b.getAttribute('data-void');
        if(!confirm('作废这条链接？作废后客户点开就提示失效。')) return;
        var t2=rgTok(); b.disabled=true;
        api('/api/regtoken_void',{user:t2.user,pass:t2.pass,code:code}).then(function(r2){
          if(r2.ok&&r2.d&&r2.d.ok){ rgLoad(); } else { b.disabled=false; alert((r2.d&&r2.d.message)||'作废失败'); }
        }).catch(function(){ b.disabled=false; alert('网络错误'); });
      };
    });
  }).catch(function(){ $('rgList').innerHTML='<div style="color:#b06a00;font-size:12px">网络错误，请重试</div>'; });
}
/* 2026-11-11：链接查询三个入口 —— 点「查询」、框里按回车、「显示全部」清条件回最近列表 */
$('rgQBt').onclick=function(){ rgLoad(); };
$('rgQAll').onclick=function(){ if($('rgQ'))$('rgQ').value=''; if($('rgState'))$('rgState').value=''; rgLoad(); };
if($('rgQ')){ $('rgQ').onkeydown=function(e){ if((e.key||e.keyCode)===13||e.key==='Enter'){ rgLoad(); } }; }
$('btnCfg').onclick=function(){
  var c=(DATA&&DATA.cfg)||{agents:[],plans:[]};
  // 2026-11-06：名单框支持「客服名|群号」；有群号的客服带竖线展示
  $('cAgents').value=(c.agents||[]).map(function(a){
    var g=(c.groups||{})[a];
    return g?(a+'|'+g):a;
  }).join('\\n');
  $('cDefGrp').value=(c.default_group||'');
  $('cPlans').value=(c.plans||[]).map(function(p){return p.label+'='+p.days+'='+(p.price>=0?p.price:'');}).join('\\n');
  $('rnNew').value='';buildRenameSel();
  $('cm').textContent='';$('cfgModal').hidden=false;
};
$('rnGo').onclick=function(){
  var t=JSON.parse(TOKEN||'{}');
  var o=$('rnOld').value||'', n=($('rnNew').value||'').trim();
  if(!o){$('cm').textContent='先在左边选一个要改的客服';$('cm').className='msg err';return;}
  if(!n){$('cm').textContent='填一下新名字';$('cm').className='msg err';return;}
  if(o===n){$('cm').textContent='新旧名字一样，不用改';$('cm').className='msg err';return;}
  if(!confirm('确定把「'+o+'」改名为「'+n+'」？\\n\\n会一起改掉：登记下拉、所有已登记的号、月度结算里的成交记录。\\n这一步不可撤销（只能再改回去）。'))return;
  $('rnGo').disabled=true;$('cm').textContent='正在改…';$('cm').className='msg';
  api('/api/console/agent_rename',{user:t.user,pass:t.pass,old:o,new:n}).then(function(r){
    $('rnGo').disabled=false;
    if(r.ok&&r.d&&r.d.ok){
      $('cm').textContent=r.d.message||'已改名';$('cm').className='msg ok';
      var c=r.d.cfg||{};
      $('cAgents').value=(c.agents||[]).map(function(a){var g=(c.groups||{})[a];return g?(a+'|'+g):a;}).join('\\n');
      $('cDefGrp').value=(c.default_group||'');
      $('rnNew').value='';buildRenameSel();loadData();
    }else{
      $('cm').textContent=(r.d&&r.d.message)||'改名失败';$('cm').className='msg err';
    }
  }).catch(function(){$('rnGo').disabled=false;$('cm').textContent='网络错误，请重试';$('cm').className='msg err';});
};
$('cCancel').onclick=function(){$('cfgModal').hidden=true;};
$('cSave').onclick=function(){
  var t=JSON.parse(TOKEN||'{}');
  // 2026-11-06：名单行支持「客服名|群号」。解析后：agents 只留名字（登记下拉口径不变），
  //   groups 单独传给后端。群号只留数字；竖线后为空 = 该客服不配群号。
  var agents=[],groups={};
  $('cAgents').value.split('\\n').map(function(s){return s.trim();}).filter(Boolean).forEach(function(s){
    var i=s.indexOf('|'),nm=s,g='';
    if(i>=0){nm=s.slice(0,i).trim();g=s.slice(i+1).trim().replace(/[^0-9]/g,'');}
    if(!nm)return;
    if(agents.indexOf(nm)<0)agents.push(nm);
    if(g)groups[nm]=g;
  });
  var dgrp=$('cDefGrp').value.trim().replace(/[^0-9]/g,'');
  var plans=$('cPlans').value.split('\\n').map(function(s){
    s=s.trim();if(!s)return null;
    var q=s.split('=');if(q.length<2)return null;
    var lb=q[0].trim(),dy=parseInt(q[1],10);
    if(!lb||isNaN(dy))return null;
    var o2={key:lb,label:lb,days:dy};
    // 2026-11-05：第三段 = 单价（元）。不写或留空 = 没定价，结算里进「待补价」而不是当 0 元。
    if(q.length>=3){
      var pv=q[2].trim();
      if(pv!==''){var pf=parseFloat(pv);if(!isNaN(pf)&&pf>=0)o2.price=pf;}
    }
    return o2;
  }).filter(Boolean);
  if(!agents.length||!plans.length){$('cm').textContent='客服和套餐至少要各留一条';$('cm').className='msg err';return;}
  // 2026-11-06：疑似改名先拦一下。名单框是给「加人 / 删人 / 排序」用的，
  //   在里面把一个字改掉只会换下拉，历史号和结算账本不动 —— 用户看不出两者的区别，这里明确问一次。
  var sus=suspectRename((DATA&&DATA.cfg&&DATA.cfg.agents)||[],agents);
  if(sus&&!confirm('名单里少了「'+sus.gone.join('、')+'」、多了「'+sus.add.join('、')+'」。\\n\\n'
    +'· 如果这是「改名」→ 点「取消」，改用上面的「客服改名」（否则已登记的号、结算账本还是旧名字）\\n'
    +'· 如果确实是「删掉一个客服、另外新增一个」→ 点「确定」继续保存'))return;
  $('cSave').disabled=true;
  api('/api/console/cfg',{user:t.user,pass:t.pass,agents:agents,plans:plans,groups:groups,default_group:dgrp}).then(function(o){
    $('cSave').disabled=false;
    if(o.ok&&o.d.ok){$('cm').textContent=o.d.message||'已保存';$('cm').className='msg ok';setTimeout(function(){$('cfgModal').hidden=true;loadData();},900);}
    else{$('cm').textContent=(o.d&&o.d.message)||'保存失败';$('cm').className='msg err';}
  }).catch(function(){$('cSave').disabled=false;$('cm').textContent='网络错误';$('cm').className='msg err';});
};
$('btnCsv').onclick=function(){
  var rows=[[ '池','账号','客服','套餐','UID','歌曲ID','时长(秒)',
    '昨进度','今进度','日环比',
    '近30日播放','入池','有效期','邮箱','标记','补号','备注']];
  buildRows().forEach(function(r){
    var e=r.e;
    var dur=(DATA.durs||{})[r.pool+'|'+e.uid]||(DATA.durs||{})[e.uid]||((r.a&&r.a.dur)||'');
    rows.push([r.pool==='hz'?'主群':'定制群',e.name,e.agent||'',e.plan||'',e.uid||'',e.song||'',dur,
      r.p&&r.p.rate!=null?r.p.rate:'',r.a&&r.a.rate!=null?r.a.rate:'',r.delta==null?'':r.delta,
      r.a&&r.a.rpc30!=null?r.a.rpc30:'',e.added||'',e.exp||'永久',e.email||'',e.pub?'公益号':(e.noListen?'只收':''),
      e.rb?'补号':'',e.note||'']);
  });
  var csv='\\ufeff'+rows.map(function(r){return r.map(function(v){return '"'+String(v).replace(/"/g,'""')+'"';}).join(',');}).join('\\r\\n');
  var a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
  a.download='650控制台_'+(DATA?DATA.date:todayBJ())+'.csv';
  document.body.appendChild(a);a.click();document.body.removeChild(a);
};
(function(){
  // 2026-10-27 21:05：入池日期范围默认留空 = 全部号（不筛）。要看某段就自己填。
  $('dateTo').value='';
  $('date').value='';
  // 2026-10-25：#pw= 免密改成「可重复触发」。旧版只在脚本初次执行时读一次 hash，而 CK助手再点
  // 「进阶控制台」时浏览器通常已经开着 /console 标签 —— 那只是同页内 hash 变化，脚本不会重跑，
  // 免密不执行 → 刚在 EXE 输过口令，网页又弹登录框（等于要输两遍）。现在抽成函数并监听 hashchange。
  function hashLogin(){
    var m=(location.hash||'').match(/pw=([^&]+)/)||(location.search||'').match(/[?&]pw=([^&]+)/);
    if(!m)return false;
    var pw=m[1];try{pw=decodeURIComponent(pw);}catch(e){}
    try{history.replaceState(null,'',location.pathname);}catch(e1){}   // 地址栏/历史不留明文口令
    var lb=$('loginBox'),mb=$('mainBox');
    $('lp').value=pw;
    $('lm').textContent='正在自动登录…';$('lm').className='msg';
    api('/api/console/login',{user:'xx1031',pass:pw}).then(function(o){
      if(o.ok&&o.d.ok){
        TOKEN=JSON.stringify({user:'xx1031',pass:pw});save(TOKEN,o.d.role);
        lb.hidden=true;mb.hidden=false;applyRole(o.d.role);loadData();
      }else{
        lb.hidden=false;mb.hidden=true;
        $('lm').textContent=(o.d&&o.d.message)||'免密登录失败，请重新输入控制台口令';$('lm').className='msg err';
      }
    }).catch(function(){
      lb.hidden=false;mb.hidden=true;
      $('lm').textContent='网络错误，请手动登录';$('lm').className='msg err';
    });
    return true;
  }
  window.addEventListener('hashchange',function(){hashLogin();});
  if(hashLogin())return;                    // 带 #pw= 时优先免密，不看缓存
  var s=load();
  if(s){TOKEN=s.t;applyRole(s.role);$('loginBox').hidden=true;$('mainBox').hidden=false;loadData(true);}
})();
</script></body></html>`;

// 2026-10-22：D1 绑定只支持 ES Module 格式，故入口从 addEventListener 改为
// export default { fetch }。既有代码全部按 service-worker 时代的「绑定即全局变量」
// 写法（POOL.get / GH_OWNER ...），这里在每个请求开头把 env 挂到 globalThis，
// 一行代码都不用改旧的。绑定对同一 isolate 的所有请求完全相同，挂全局是安全的。
export default {
  async fetch(request, env, ctx) {
    globalThis.POOL = env.POOL;
    globalThis.GH_OWNER = env.GH_OWNER;
    globalThis.GH_REPO = env.GH_REPO;
    if (env.DB) globalThis.DB = env.DB;
    // 2026-11-09：D1 额度探针要用的 CF 只读凭据（Account Analytics: Read）。
    // 用 Secret 存（加密、读不回），不写 KV；两者都支持，Secret 优先。
    if (env.CFQ_TOKEN) globalThis.CFQ_TOKEN = env.CFQ_TOKEN;
    if (env.CFQ_ACCOUNT) globalThis.CFQ_ACCOUNT = env.CFQ_ACCOUNT;
    // 2026-10-25：handle(request) 拿不到 ctx（签名只有 request），想用 waitUntil 做后台任务
    // 必须挂到全局。不挂的话路由里引用 ctx 会抛 ReferenceError，被 try/catch 吞掉 → 后台任务静默不执行。
    if (ctx) globalThis.CTX = ctx;
    try {
      return await handle(request);
    } catch (e) {
      return new Response(JSON.stringify({ message: '服务器内部错误：' + ((e && e.message) || e) }),
        { status: 500, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
    }
  },
  // 2026-10-24：CF 原生 cron 入口。只做一件事 —— 准点把 snap650 的 workflow_dispatch 叫起来。
  // 之所以不用 GitHub 的 schedule：本账号实测 schedule 会整体推迟 1~5 小时（relay 22:23→02:25），
  // snap650 上线两天甚至 0 次自动运行，导致控制台白天读到的仍是凌晨结算前的旧值。
  async scheduled(event, env, ctx) {
    globalThis.POOL = env.POOL;
    globalThis.GH_OWNER = env.GH_OWNER;
    globalThis.GH_REPO = env.GH_REPO;
    if (env.DB) globalThis.DB = env.DB;
    if (env.CFQ_TOKEN) globalThis.CFQ_TOKEN = env.CFQ_TOKEN;
    if (env.CFQ_ACCOUNT) globalThis.CFQ_ACCOUNT = env.CFQ_ACCOUNT;
    // 2026-11-05：按 event.cron 分流。新加的 3 个时刻只负责「备份发令」，
    // 不能顺带把 snap650 / 到期清理 / 元数据补全都再跑一遍（那会变成一天 4 次快照采集）。
    // 老时刻（10 2 * * *）以及取不到 cron 的情况一律走原来的全量路径，行为不变。
    const _cron = String((event && event.cron) || '');
    if (BACKUP_CRONS.indexOf(_cron) >= 0) {
      ctx.waitUntil(dispatchDailyBackup(_cron).catch(() => {}));
      return;
    }
    // 2026-11-06：邮件队列发令腿（北京每小时 :05/:35），只发令不干别的，跑完即 return。
    if (MAIL_CRONS.indexOf(_cron) >= 0) {
      ctx.waitUntil(dispatchMailQueue().catch(() => {}));
      // 2026-11-09：每小时顺带探一次 D1 额度水位（relay 停跑时也能刷新，
      // 否则闸门数据超过 90 分钟就判「未知」，等于白做）。
      ctx.waitUntil(d1QuotaProbe().catch(() => {}));
      // 2026-11-10：重放「登记成功但没写进 D1」的补偿队列（relay 停跑时也有兜底腿）
      ctx.waitUntil(replayFixups().catch(() => {}));
      return;
    }
    ctx.waitUntil(dispatchSnap650('all').catch(() => {}));
    // 2026-11-09：主 cron 也刷新一次额度水位（每天 1 次，兜住 scheduled 分支变动）。
    ctx.waitUntil(d1QuotaProbe(true).catch(() => {}));
    // 2026-10-29：到期号清理挪进每日 cron。
    // 以前 pruneExpired 全项目只有 /api/pool（旧「号池管理后台」页面）一个调用点 ——
    // 谁打开那个工具谁才清。后果三连：到期号一直挂在池里（只是不播放）；号主收不到
    // 「账号信息过期」；重新登记被 addEntry 判成「已登记过」直接拒绝。这里每天清一次，
    // 语义与工具里点一次完全一致（同样的墓碑、D1 删除、通知入队）。
    ctx.waitUntil((async () => {
      try {
        const r = await pruneExpired();
        if (r && r.count) console.log('scheduled 已到期降级公益号 ' + r.count + ' 个（不再删除）');
      } catch (e) { console.error('scheduled 到期降级失败:', (e && e.message) || e); }
    })());
    // 2026-11-09：CK 失效超时清理（relogin_at 非空且超过 RELOGIN_TTL_DAYS，默认 7 天）。
    // 这些号早已被摘出听众环、不会再被任何请求上报，只能靠定时器收尾。
    // 放在主 cron（北京 10:00）：两轮之间，不碰当天 plan_snap，也不影响 11:40 的表快照采集。
    ctx.waitUntil((async () => {
      try {
        const r = await pruneStaleRelogin();
        if (r && r.removed) console.log('scheduled relogin 超时清理删除 ' + r.removed + ' 个：' + (r.names || []).join('、'));
      } catch (e) { console.error('scheduled relogin 超时清理失败:', (e && e.message) || e); }
    })());
    // 对端（定制群 dz）没有 scheduled handler，定时全靠 GitHub —— 这里用对穿口令让它在自己池里跑一遍。
    // 失败只记日志，绝不影响本群流程；对端没配 PEER_KEY 就直接跳过。
    ctx.waitUntil((async () => {
      try {
        const pk = await peerKey();
        if (!pk) return;
        const purl = (cleanKV(await POOL.get('PEER_URL')) || PEER_DEFAULT).replace(/\/+$/, '');
        const r = await fetch(purl + '/api/relogin_sweep', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'User-Agent': 'cron-relay-worker' },
          body: JSON.stringify({ pass: pk }),
        });
        const d = await r.json().catch(() => null);
        if (d && d.ok && d.removed) console.log('对端 relogin 超时清理删除 ' + d.removed + ' 个：' + (d.names || []).join('、'));
        else if (d && d.ok === false) console.log('对端 relogin 超时清理返回失败：' + (d.msg || d.message || ''));
      } catch (e) { console.log('对端 relogin 超时清理调用失败（忽略）:', (e && e.message) || e); }
    })());
    // 2026-10-25：每天顺手补一批歌曲/账号元数据（控制台「共创歌曲 / 绑错歌」标签的数据源）。
    // 本地 IP 被网易限流，只能靠 Worker 出口；每天 30 个号 + 12 首歌，新号基本当天就能补上。
    ctx.waitUntil(backfillMeta().catch(() => {}));
    // 2026-11-05：快照只保留最近 90 天（SNAP_KEEP_DAYS）。放在主 cron 而不是 BACKUP_CRONS 那条分支 ——
    // 那三条是纯「备份发令」，跑了就 return，不该顺带做任何清理。
    ctx.waitUntil((async () => {
      try {
        const r = await purgeOldSnapshots();
        if (r && r.deleted) console.log('scheduled 已清理 ' + r.deleted + ' 条 90 天前快照（截止 ' + r.cutoff + '）');
      } catch (e) { console.error('scheduled 快照清理失败:', (e && e.message) || e); }
    })());
  }
};
