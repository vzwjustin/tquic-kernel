[
  {
    "category": "Loss Detection",
    "description": "Fix PTO time calculation to use per-path RTT",
    "steps": [
      "Modify tquic_loss_get_pto_time_space to accept or determine the correct path",
      "Update callers of tquic_loss_get_pto_time_space to pass the relevant path context",
      "Ensure calculations use path->rtt instead of active_path->rtt"
    ],
    "passes": true
  },
  {
    "category": "Loss Detection",
    "description": "Fix loss detection timer to use per-path state",
    "steps": [
      "Modify tquic_set_loss_detection_timer to evaluate timers on a per-path basis or correctly aggregate",
      "Ensure timer deadlines reflect the specific path's RTT and PTO"
    ],
    "passes": true
  },
  {
    "category": "Congestion Control",
    "description": "Fix persistent congestion checks to use per-path RTT",
    "steps": [
      "Modify tquic_loss_persistent_congestion to accept a path context",
      "Update callers to pass the correct path from the lost packet",
      "Calculate persistent congestion duration using the specific path's RTT"
    ],
    "passes": true
  },
  {
    "category": "Cleanup",
    "description": "Fix bytes_in_flight cleanup during key discard",
    "steps": [
      "Modify tquic_loss_discard_pn_space_keys to compute removed_bytes per path",
      "Ensure path->cc.bytes_in_flight is properly decremented for each specific path",
      "Avoid using active path for clearing dropped in-flight packets"
    ],
    "passes": true
  }
]
