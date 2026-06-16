"""
BayesianMCTS - Probabilistic attack planning system for RedTeam V9.
Replaces naive branch scoring with proper Bayesian reasoning from evidence.
"""
import math
import json
import time
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

ATTACK_TYPES = [
    "sqli", "xss", "xpath_injection", "command_injection",
    "auth_bypass", "idor", "csrf", "session_fixation",
    "header_misconfiguration", "cookie_analysis", "nuclei_scan",
    "directory_enumeration", "fingerprinting"
]

@dataclass
class MCTSNode:
    attack_type: str
    visit_count: int = 0
    total_reward: float = 0.0
    prior_probability: float = 0.1
    posterior_probability: float = 0.1
    confidence: float = 0.0
    entropy: float = 1.0
    children: List['MCTSNode'] = field(default_factory=list)
    parent: Optional['MCTSNode'] = None
    evidence_log: List[dict] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def ucb1_score(self, parent_visits: int, C: float = 1.414, alpha: float = 0.3) -> float:
        if self.visit_count == 0:
            return float('inf')
        exploitation = self.total_reward / self.visit_count
        exploration = C * math.sqrt(math.log(max(parent_visits, 1)) / self.visit_count)
        prior_bonus = alpha * self.posterior_probability
        return exploitation + exploration + prior_bonus

    def effective_evidence_weight(self, current_step: int, decay_rate: float = 0.05) -> float:
        weights = []
        for ev in self.evidence_log:
            age = current_step - ev.get("step", current_step)
            w = ev.get("weight", 1.0) * math.exp(-decay_rate * age)
            weights.append(w)
        return sum(weights) if weights else 0.0

    def to_dict(self) -> dict:
        return {
            "attack_type": self.attack_type,
            "visit_count": self.visit_count,
            "total_reward": self.total_reward,
            "prior_probability": self.prior_probability,
            "posterior_probability": self.posterior_probability,
            "confidence": self.confidence,
            "entropy": self.entropy,
            "evidence_count": len(self.evidence_log),
        }


class BayesianMCTS:
    """
    Bayesian-MCTS hybrid scorer. Maintains a tree of attack candidates
    and updates probabilities based on fingerprint evidence and tool results.
    """

    def __init__(self, session_id: str, decay_rate: float = 0.05):
        self.session_id = session_id
        self.decay_rate = decay_rate
        self.step_counter = 0
        self.root = MCTSNode(attack_type="root", prior_probability=1.0, posterior_probability=1.0)
        self._nodes: Dict[str, MCTSNode] = {}
        self._initialise_children()

    def _initialise_children(self):
        for at in ATTACK_TYPES:
            node = MCTSNode(attack_type=at, parent=self.root)
            self.root.children.append(node)
            self._nodes[at] = node

    def apply_fingerprint_priors(self, fingerprint: dict):
        """
        Update prior probabilities based on target fingerprint.
        These are soft Bayesian priors, not hard rules.
        """
        priors = {at: 0.1 for at in ATTACK_TYPES}

        techs = json.dumps(fingerprint).lower()

        if "php" in techs:
            priors["sqli"] = min(priors["sqli"] + 0.3, 1.0)
            priors["xss"] = min(priors["xss"] + 0.2, 1.0)

        if "jwt" in techs or "session" in techs:
            priors["session_fixation"] = min(priors["session_fixation"] + 0.4, 1.0)

        if "form" in techs or "input" in techs:
            priors["csrf"] = min(priors["csrf"] + 0.3, 1.0)
            priors["sqli"] = min(priors["sqli"] + 0.2, 1.0)

        if "login" in techs or "auth" in techs or "signin" in techs:
            priors["auth_bypass"] = min(priors["auth_bypass"] + 0.5, 1.0)

        if "api" in techs or "rest" in techs or "json" in techs:
            priors["idor"] = min(priors["idor"] + 0.4, 1.0)

        if "apache" in techs or "nginx" in techs or "iis" in techs:
            priors["header_misconfiguration"] = min(priors["header_misconfiguration"] + 0.3, 1.0)

        # Normalise and apply
        total = sum(priors.values()) or 1.0
        for at, p in priors.items():
            if at in self._nodes:
                self._nodes[at].prior_probability = p / total
                self._nodes[at].posterior_probability = p / total

        self._recompute_entropy()
        logger.info(f"[{self.session_id}] Fingerprint priors applied: {priors}")

    def apply_transfer_priors(self, transfer_rows: List[dict]):
        """
        Blend transfer learning success rates into current priors.
        transfer_rows: [{attack_type, success_rate, sample_count}, ...]
        """
        for row in transfer_rows:
            at = row.get("attack_type")
            if at in self._nodes:
                sr = row.get("success_rate", 0.0)
                sc = row.get("sample_count", 1)
                weight = min(sc / 10.0, 1.0)  # cap weight at 10 samples
                node = self._nodes[at]
                blended = (1 - weight) * node.prior_probability + weight * sr
                node.prior_probability = blended
                node.posterior_probability = blended
        self._recompute_entropy()

    def select(self, top_k: int = 5) -> List[dict]:
        """
        UCB1 selection: return top_k attack types ranked by score.
        Returns list of {attack_type, score, confidence, entropy, posterior}.
        """
        self.step_counter += 1
        scores = []
        parent_visits = self.root.visit_count or 1

        for node in self.root.children:
            score = node.ucb1_score(parent_visits)
            # Replace inf (unvisited node sentinel) with a concrete large value
            # so the result is always JSON-serialisable
            if score == float('inf') or math.isinf(score) or math.isnan(score):
                score = 99.0
            scores.append({
                "attack_type": node.attack_type,
                "score": round(score, 4),
                "confidence": round(node.confidence, 4),
                "entropy": round(node.entropy, 4),
                "posterior": round(node.posterior_probability, 4),
                "visit_count": node.visit_count,
            })

        scores.sort(key=lambda x: x["score"], reverse=True)
        return scores[:top_k]

    def simulate(self, attack_type: str, rag_hit_count: int, max_rag_hits: int,
                 historical_success_rate: float) -> float:
        """
        Lightweight heuristic rollout estimate (no real tool execution).
        reward = (rag_hit_count / max_rag_hits) * historical_success_rate
        """
        if max_rag_hits == 0:
            return 0.0
        return (rag_hit_count / max_rag_hits) * max(historical_success_rate, 0.1)

    def backpropagate(self, attack_type: str, actual_reward: float,
                      evidence: Optional[dict] = None):
        """
        Update node after real tool execution.
        actual_reward: 1.0 confirmed vuln, 0.5 injection point, 0.0 clean.
        """
        node = self._nodes.get(attack_type)
        if node is None:
            return

        node.visit_count += 1
        node.total_reward += actual_reward
        self.root.visit_count += 1

        # Update confidence as running average
        node.confidence = node.total_reward / node.visit_count

        # Update posterior via simple Bayesian update
        # P(success | evidence) ∝ P(evidence | success) * P(prior)
        likelihood = actual_reward * 0.8 + 0.1  # smoothed
        unnorm = likelihood * node.prior_probability
        node.posterior_probability = min(unnorm, 1.0)

        if evidence:
            evidence["step"] = self.step_counter
            evidence["weight"] = actual_reward if actual_reward > 0 else 0.1
            node.evidence_log.append(evidence)

        self._recompute_entropy()
        logger.debug(f"[{self.session_id}] Backprop {attack_type}: reward={actual_reward}, "
                     f"confidence={node.confidence:.3f}")

    def _recompute_entropy(self):
        """Compute Shannon entropy over child posterior probabilities."""
        posteriors = [n.posterior_probability for n in self.root.children if n.posterior_probability > 0]
        total = sum(posteriors) or 1.0
        normalised = [p / total for p in posteriors]
        H = -sum(p * math.log2(p) for p in normalised if p > 0)
        # Apply to all children as their branch entropy
        for node in self.root.children:
            node.entropy = round(H, 4)
        self.root.entropy = round(H, 4)

    def get_state(self) -> dict:
        return {
            "session_id": self.session_id,
            "step_counter": self.step_counter,
            "root_visits": self.root.visit_count,
            "root_entropy": self.root.entropy,
            "nodes": [n.to_dict() for n in self.root.children],
        }


# Module-level registry: session_id → BayesianMCTS
_mcts_registry: Dict[str, BayesianMCTS] = {}

def get_or_create_mcts(session_id: str) -> BayesianMCTS:
    if session_id not in _mcts_registry:
        _mcts_registry[session_id] = BayesianMCTS(session_id)
    return _mcts_registry[session_id]

def remove_mcts(session_id: str):
    _mcts_registry.pop(session_id, None)
