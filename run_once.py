# -*- coding: utf-8 -*-
# =============================================================================
#  【安全声明】本文件为校园跑（成都理工大学体育打卡小程序）安全漏洞的概念验证
#  （PoC）代码，仅用于安全研究、学习交流与向校方上报漏洞之目的。
#  严禁用于任何非法用途或真实的成绩作弊；由此产生的一切后果与作者本人无关。
#  详见仓库根目录 安全声明.md。
# =============================================================================
"""
自动获取当前微信小程序账户的 au，并按已验证的校园内缩 GPS 路径完成一次有效记录。

默认真实耗时约 19~20 分钟。先只检查 token：
  py -3.12 auto_au.py

执行一次：
  py -3.12 run_once.py
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import os
import random
import struct
import sys
import time
import zlib
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import requests

import auto_au


APPID = auto_au.APPID
BASE = os.environ.get("CDUT_BASE", auto_au.BASE).rstrip("/")
ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT / "runtime"
LOG_PATH = ROOT / "run_once.log"
STATE_PATH = ROOT / "run_once_state.json"

SPORT_SUBJECT = 1
DEFAULT_SHRINK = 0.53
SERVER_DISTANCE_RATIO = 0.968


class Runner:
    def __init__(self, au: str):
        self.au = au
        self.s = requests.Session()
        self.s.headers.update(auto_au.mini_headers(au))

    def post(self, path: str, data: Dict[str, Any] | None = None, *, timeout: float = 15.0, think: bool = True) -> Any:
        if data is None:
            data = {}
        if think:
            time.sleep(random.uniform(0.08, 0.35))
        body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        r = self.s.post(BASE + path, data=body, timeout=timeout)
        try:
            j = r.json()
        except Exception:
            raise RuntimeError(f"{path} HTTP {r.status_code}: {r.text[:500]}")
        if j.get("code") != 0:
            raise RuntimeError(f"{path} code={j.get('code')} msg={j.get('msg')} body={j}")
        return j.get("data")

    def upload_file(self, tag: str) -> str:
        RUNTIME.mkdir(exist_ok=True)
        p = RUNTIME / f"wx_camera_{tag}_{time.strftime('%Y%m%d_%H%M%S')}_{random.randint(1000,9999)}.png"
        make_camera_like_png(p)
        headers = auto_au.mini_headers(self.au)
        headers.pop("Content-Type", None)
        with p.open("rb") as f:
            files = {"file": (p.name, f, "image/png")}
            r = requests.post(BASE + "/api/file/upload", headers=headers, files=files, timeout=25)
        try:
            j = r.json()
        except Exception:
            raise RuntimeError(f"upload HTTP {r.status_code}: {r.text[:500]}")
        if j.get("code") != 0:
            raise RuntimeError(f"upload failed: {j}")
        return j["data"]["bean"]["fileUrl"]


def log(msg: str) -> None:
    ROOT.mkdir(exist_ok=True)
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def save_state(st: Dict[str, Any]) -> None:
    STATE_PATH.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)


def make_camera_like_png(path: Path, width: int = 480, height: int = 320) -> None:
    # 纯 stdlib 生成一张非 1x1 的 PNG，避免上传文件尺寸/内容过于固定。
    rnd = random.Random(time.time_ns() ^ random.getrandbits(64))
    base_r = rnd.randint(80, 150)
    base_g = rnd.randint(90, 170)
    base_b = rnd.randint(80, 150)
    rows = []
    for y in range(height):
        row = bytearray([0])
        gy = int(25 * math.sin(y / 27.0 + rnd.random()))
        for x in range(width):
            gx = int(22 * math.sin(x / 31.0))
            noise = rnd.randint(-12, 12)
            r = max(0, min(255, base_r + gx + gy + noise))
            g = max(0, min(255, base_g + gx // 2 + gy + noise))
            b = max(0, min(255, base_b + gx // 3 + gy // 2 + noise))
            row.extend((r, g, b))
        rows.append(bytes(row))
    raw = b"".join(rows)
    payload = (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + png_chunk(b"IDAT", zlib.compress(raw, level=6))
        + png_chunk(b"IEND", b"")
    )
    path.write_bytes(payload)


def hav(a: Dict[str, float], b: Dict[str, float]) -> float:
    R = 6371000.0
    lat1, lon1 = math.radians(a["lat"]), math.radians(a["lng"])
    lat2, lon2 = math.radians(b["lat"]), math.radians(b["lng"])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * R * math.asin(math.sqrt(h))


def normalize_poly(line_gps: Any) -> List[Dict[str, float]]:
    raw = json.loads(line_gps) if isinstance(line_gps, str) else line_gps
    out: List[Dict[str, float]] = []
    for p in raw:
        if isinstance(p, dict):
            lat = p.get("lat", p.get("latitude"))
            lng = p.get("lng", p.get("longitude"))
        elif isinstance(p, (list, tuple)) and len(p) >= 2:
            lat, lng = p[0], p[1]
        else:
            continue
        out.append({"lat": float(lat), "lng": float(lng)})
    if len(out) < 3:
        raise RuntimeError("lineGps 解析失败或点数不足")
    return out


def polygon_center(poly: List[Dict[str, float]]) -> Dict[str, float]:
    return {"lat": sum(p["lat"] for p in poly) / len(poly), "lng": sum(p["lng"] for p in poly) / len(poly)}


def shrink_polygon(poly: List[Dict[str, float]], factor: float) -> List[Dict[str, float]]:
    c = polygon_center(poly)
    return [{"lat": c["lat"] + (p["lat"] - c["lat"]) * factor, "lng": c["lng"] + (p["lng"] - c["lng"]) * factor} for p in poly]


def point_in_poly(p: Dict[str, float], poly: List[Dict[str, float]]) -> bool:
    x, y = p["lng"], p["lat"]
    inside = False
    j = len(poly) - 1
    for i in range(len(poly)):
        xi, yi = poly[i]["lng"], poly[i]["lat"]
        xj, yj = poly[j]["lng"], poly[j]["lat"]
        if ((yi > y) != (yj > y)) and (x < (xj - xi) * (y - yi) / ((yj - yi) or 1e-12) + xi):
            inside = not inside
        j = i
    return inside


def loop_len(points: List[Dict[str, float]]) -> float:
    return sum(hav(points[i - 1], points[i]) for i in range(1, len(points))) + hav(points[-1], points[0])


def interp(a: Dict[str, float], b: Dict[str, float], frac: float) -> Dict[str, float]:
    return {"lat": a["lat"] + (b["lat"] - a["lat"]) * frac, "lng": a["lng"] + (b["lng"] - a["lng"]) * frac}


def make_repeated_loop(points: List[Dict[str, float]], total_dist: float, count: int) -> Tuple[List[Dict[str, float]], float]:
    closed = points + [points[0]]
    segs = [hav(closed[i - 1], closed[i]) for i in range(1, len(closed))]
    per = sum(segs)
    out: List[Dict[str, float]] = []
    for k in range(count):
        target = total_dist * k / max(1, count - 1)
        d = target % per
        acc = 0.0
        for i, seg in enumerate(segs, start=1):
            if acc + seg >= d:
                out.append(interp(closed[i - 1], closed[i], (d - acc) / max(seg, 1e-9)))
                break
            acc += seg
        else:
            out.append(points[-1])
    return out, per


def jitter_point(p: Dict[str, float], outer_poly: List[Dict[str, float]], jitter_m: float) -> Dict[str, float]:
    for _ in range(12):
        jm = random.uniform(-jitter_m, jitter_m)
        kn = random.uniform(-jitter_m, jitter_m)
        q = {
            "lat": p["lat"] + jm / 111320.0,
            "lng": p["lng"] + kn / (111320.0 * math.cos(math.radians(p["lat"]))),
        }
        if point_in_poly(q, outer_poly):
            return q
    return p


def make_loc(p: Dict[str, float], outer_poly: List[Dict[str, float]], speed: float) -> Dict[str, Any]:
    q = jitter_point(p, outer_poly, random.uniform(0.6, 1.6))
    acc = random.triangular(4.5, 13.0, 7.5)
    return {
        "latitude": round(q["lat"], 8),
        "longitude": round(q["lng"], 8),
        "speed": round(max(0.5, random.gauss(speed, 0.10)), 3),
        "accuracy": round(acc, 2),
        "altitude": round(random.uniform(492.0, 503.0), 2),
        "verticalAccuracy": round(random.uniform(6.0, 15.0), 2),
        "horizontalAccuracy": round(acc + random.uniform(-0.8, 1.2), 2),
    }


def make_schedule(total_duration: float, warmup: float, finish_pause: float) -> List[float]:
    motion_end = total_duration - finish_pause
    t = warmup
    times = [t]
    while t < motion_end - 4.0:
        t += random.uniform(4.55, 6.15)
        if t < motion_end - 1.0:
            times.append(t)
    if motion_end - times[-1] > 2.0:
        times.append(motion_end)
    return times


def parse_rule_pair(value: Any) -> Tuple[float, float] | None:
    if value is None:
        return None
    if isinstance(value, str):
        parts = [p.strip() for p in value.split(",")]
    elif isinstance(value, (list, tuple)):
        parts = list(value)
    else:
        return None
    if len(parts) < 2:
        return None
    try:
        return float(parts[0]), float(parts[1])
    except Exception:
        return None


def choose_plan(rules: Dict[str, Any], args: argparse.Namespace) -> Dict[str, Any]:
    distance = random.uniform(args.distance_min, args.distance_max)
    expected_server_distance = distance * SERVER_DISTANCE_RATIO
    # 目标服务器侧配速 4'27''~4'34''/km，避开过快边界。
    pace_sec_per_km = random.uniform(args.pace_min, args.pace_max)
    duration = int(round((expected_server_distance / 1000.0) * pace_sec_per_km))

    time_rule = parse_rule_pair(rules.get("timeRule"))
    if time_rule:
        duration = int(max(time_rule[0] + 20, min(duration, time_rule[1] - 20)))
    speed_rule = parse_rule_pair(rules.get("speedRule"))
    if speed_rule:
        pace_sec_per_km = max(speed_rule[0] + 15, min(pace_sec_per_km, speed_rule[1] - 15))

    warmup = random.uniform(3.0, 8.0)
    finish_pause = random.uniform(2.0, 5.5)
    motion_duration = max(60.0, duration - warmup - finish_pause)
    loc_speed = distance / motion_duration
    total_steps_target = int(round(distance / random.uniform(1.18, 1.34)))
    return {
        "targetDistance": round(distance, 1),
        "expectedServerDistance": round(expected_server_distance, 1),
        "durationSec": duration,
        "targetServerPaceSecPerKm": round(pace_sec_per_km, 1),
        "warmupSec": round(warmup, 2),
        "finishPauseSec": round(finish_pause, 2),
        "motionDurationSec": round(motion_duration, 2),
        "locSpeed": round(loc_speed, 3),
        "totalStepsTarget": total_steps_target,
    }


def run(args: argparse.Namespace) -> None:
    random.seed(time.time_ns() ^ os.getpid())
    RUNTIME.mkdir(exist_ok=True)

    au_data = auto_au.get_valid_au(prefer_cache=args.cache_first, validate=True, verbose=args.verbose)
    au = au_data["au"]
    user_info = au_data.get("userInfo") or {}
    log("au ok: " + json.dumps({k: user_info.get(k) for k in ("userId", "userCode", "userName", "classCode") if k in user_info}, ensure_ascii=False))

    cli = Runner(au)
    rules_data = cli.post("/api/applet/soprt/user/check/rules", {}, timeout=15)
    rules = (rules_data or {}).get("bean") or {}
    before = (cli.post("/api/applet/soprt/result", {}, timeout=15) or {}).get("bean") or {}
    log(f"before sportNum={before.get('sportNum')} milage={before.get('sportMilage')} expend={before.get('expendTime')}")
    log(f"rules type={rules.get('type')} milage={rules.get('milage')} timeRule={rules.get('timeRule')} speedRule={rules.get('speedRule')} limitTime={rules.get('limitTime')}")

    outer = normalize_poly(rules["lineGps"])
    shrink = args.shrink if args.shrink else random.uniform(0.50, 0.56)
    inner = shrink_polygon(outer, shrink)
    inner_inside = sum(1 for p in inner if point_in_poly(p, outer))
    if inner_inside < max(3, int(len(inner) * 0.85)):
        # 极端凹多边形时继续向中心收缩。
        shrink = min(shrink, 0.42)
        inner = shrink_polygon(outer, shrink)

    plan = choose_plan(rules, args)
    schedule = make_schedule(plan["durationSec"], plan["warmupSec"], plan["finishPauseSec"])
    route, per = make_repeated_loop(inner, plan["targetDistance"], len(schedule))
    plan.update({"points": len(route), "innerPerimeter": round(per, 1), "shrink": round(shrink, 3)})
    log("plan: " + json.dumps(plan, ensure_ascii=False))

    if args.dry_run:
        save_state({"dryRun": True, "auUser": user_info, "rules": {k: rules.get(k) for k in ("type", "milage", "timeRule", "speedRule", "limitTime")}, "plan": plan})
        log("dry-run done")
        return

    time.sleep(random.uniform(1.0, 2.8))
    start_file = cli.upload_file("start")
    start_payload = {"sportSubject": SPORT_SUBJECT, "stepNum": 0, "fileUrl": start_file, "lockGpsJspn": "[]"}
    start = (cli.post("/api/applet/soprt/start", start_payload, timeout=20) or {}).get("bean") or {}
    sport_id = start["id"]
    log(f"started sportId={sport_id} startTime={start.get('startTime')}")
    state: Dict[str, Any] = {"sportId": sport_id, "start": start, "plan": plan, "idx": 0, "userInfo": user_info}
    save_state(state)

    t0 = time.time()
    start_ms = int(t0 * 1000)
    last_loc = make_loc(route[0], outer, plan["locSpeed"])
    server_total = 0
    total_steps = 0

    for idx, p in enumerate(route):
        target_t = t0 + schedule[idx]
        now = time.time()
        if target_t > now:
            time.sleep(target_t - now)

        speed = plan["locSpeed"] + random.uniform(-0.12, 0.12)
        loc = make_loc(p, outer, speed)
        if idx == 0:
            last_loc = loc.copy()

        if idx == len(route) - 1:
            step_delta = max(1, plan["totalStepsTarget"] - total_steps)
        else:
            avg = plan["totalStepsTarget"] / max(1, len(route) - 1)
            step_delta = int(max(5, min(28, random.gauss(avg, 3.2))))
            total_steps += step_delta

        gps = dict(loc)
        gps.update(
            {
                "sportId": sport_id,
                "curTime": int(time.time() * 1000),
                "steps": step_delta,
                "lastLocation": last_loc,
            }
        )
        data = cli.post("/coll/collect/sport/gps", {"gpsInfo": json.dumps(gps, ensure_ascii=False, separators=(",", ":"))}, timeout=20, think=False)
        bean = (data or {}).get("bean") or {}
        server_total = bean.get("totalMilage") or bean.get("totalMileage") or server_total
        last_loc = loc.copy()

        elapsed = int(time.time() - t0)
        state.update({"idx": idx, "lastTotalMilage": server_total, "lastPoint": loc, "elapsedSec": elapsed, "totalSteps": total_steps})
        save_state(state)
        if idx % 12 == 0 or idx == len(route) - 1:
            client_dist = plan["targetDistance"] * idx / max(1, len(route) - 1)
            pace = elapsed / max((server_total or 1) / 1000, 0.001) if server_total else 0
            log(f"gps idx={idx}/{len(route)-1} elapsed={elapsed}s clientDist={client_dist:.1f}m serverTotal={server_total} serverPace={pace:.0f}s/km")

    end_target = t0 + plan["durationSec"]
    if end_target > time.time():
        time.sleep(end_target - time.time())

    log("target reached; update state=0")
    upd = cli.post("/api/applet/soprt/update/state", {"sportId": sport_id, "state": 0, "speedNum": 0}, timeout=20)
    log(f"update ok: {(upd or {}).get('bean') or upd}")

    end_file = cli.upload_file("end")
    end_payload = {"sportId": sport_id, "stepNum": int(total_steps), "fileUrl": end_file, "abnormalStop": 1, "reason": "正常结束"}
    end = cli.post("/api/applet/soprt/end", end_payload, timeout=35)
    log(f"end ok: {(end or {}).get('bean') or end}")

    latest = None
    after = None
    for attempt in range(1, 7):
        time.sleep(random.uniform(2.2, 5.2))
        after = (cli.post("/api/applet/soprt/result", {}, timeout=15) or {}).get("bean") or {}
        lst = cli.post(
            "/api/applet/soprt/list",
            {"pageNum": 1, "pageSize": 5, "sportSubject": "", "sportType": "", "sportState": "", "sportDateStart": "", "sportDateEnd": ""},
            timeout=20,
        )
        rows = (lst or {}).get("list") or []
        latest = rows[0] if rows else None
        if latest and latest.get("id") == sport_id and latest.get("sportState") in (9, 11):
            break
        log(f"poll attempt={attempt} resultSportNum={after.get('sportNum')} latestId={(latest or {}).get('id')} state={(latest or {}).get('sportState')}")

    if after:
        log(f"after sportNum={after.get('sportNum')} milage={after.get('sportMilage')} expend={after.get('expendTime')}")
    if latest:
        keys = ["id", "sportSubject", "sportType", "sportState", "sportMilage", "expendTime", "startTime", "finishTime", "endTime", "averageSpeed", "maxSpeed", "minSpeed"]
        log("latest record: " + json.dumps({k: latest.get(k) for k in keys}, ensure_ascii=False))
    state.update({"finished": True, "after": after, "latest": latest})
    save_state(state)
    log("DONE")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="只取 token/规则并生成计划，不 start/gps/end")
    ap.add_argument("--cache-first", action="store_true", help="优先使用缓存 token；默认扫描当前微信进程")
    ap.add_argument("--distance-min", type=float, default=4480.0)
    ap.add_argument("--distance-max", type=float, default=4620.0)
    ap.add_argument("--pace-min", type=float, default=267.0, help="服务器侧目标配速秒/公里，默认约 4'27''")
    ap.add_argument("--pace-max", type=float, default=274.0, help="服务器侧目标配速秒/公里，默认约 4'34''")
    ap.add_argument("--shrink", type=float, default=0.0, help="GPS 多边形内缩比例，默认随机 0.50~0.56")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    try:
        run(args)
        return 0
    except KeyboardInterrupt:
        log("INTERRUPTED")
        return 130
    except Exception as exc:
        log("ERROR: " + repr(exc))
        raise


if __name__ == "__main__":
    raise SystemExit(main())

