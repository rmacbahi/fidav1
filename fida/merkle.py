from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple
from fida.util import sha256_hex

def _h(a: str, b: str) -> str:
    return sha256_hex((a + b).encode("utf-8"))

@dataclass
class MerkleProof:
    leaf: str
    index: int
    siblings: List[Tuple[str, str]]  # (side, hash) side is "L" or "R"
    root: str

def build_merkle(leaves: List[str]) -> tuple[str, list[list[str]]]:
    if not leaves:
        # define empty root as sha256("")
        return sha256_hex(b""), [[sha256_hex(b"")]]
    level = leaves[:]
    layers = [level]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i+1] if i+1 < len(level) else left
            nxt.append(_h(left, right))
        level = nxt
        layers.append(level)
    return layers[-1][0], layers

def prove(layers: list[list[str]], index: int) -> MerkleProof:
    leaf = layers[0][index]
    siblings: List[Tuple[str, str]] = []
    idx = index
    for lvl in range(len(layers)-1):
        layer = layers[lvl]
        is_right = (idx % 2 == 1)
        sib_idx = idx-1 if is_right else idx+1
        sib = layer[sib_idx] if sib_idx < len(layer) else layer[idx]
        siblings.append(("L", sib) if is_right else ("R", sib))
        idx //= 2
    return MerkleProof(leaf=leaf, index=index, siblings=siblings, root=layers[-1][0])

def verify_proof(p: MerkleProof) -> bool:
    cur = p.leaf
    idx = p.index
    for side, sib in p.siblings:
        if side == "L":
            cur = _h(sib, cur)
        else:
            cur = _h(cur, sib)
        idx //= 2
    return cur == p.root
