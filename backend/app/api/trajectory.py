"""
CyberSentinel Attack Trajectory & Predictive Intelligence API Router.
"""

from __future__ import annotations

from typing import Any, Dict, List
from fastapi import APIRouter
from backend.app.prediction import get_engine as get_traj_engine

router = APIRouter(tags=["Trajectory"])

@router.get("/api/trajectory")
def get_all_trajectories():
    engine = get_traj_engine()
    trajectories = engine.get_all_trajectories()
    return {"count": len(trajectories), "trajectories": trajectories}

@router.get("/api/trajectory/{source_ip}")
def get_trajectory_for_ip(source_ip: str):
    engine = get_traj_engine()
    return engine.get_trajectory(source_ip)
