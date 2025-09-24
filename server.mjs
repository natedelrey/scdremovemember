import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import noblox from "noblox.js";

/**
 * Supported ENV:
 * PORT (Railway sets; default 8080)
 * ROBLOSECURITY
 * ROBLOX_GROUP_ID  (preferred)  | GROUP_ID (fallback)
 * ROBLOX_REMOVE_SECRET (preferred) | RANK_SERVICE_SECRET / SERVICE_SECRET (fallback)
 */

const PORT = Number(process.env.PORT || 8080);

// Prefer Python-bot naming; accept legacy fallbacks
const GROUP_ID =
  Number(process.env.ROBLOX_GROUP_ID) ||
  Number(process.env.GROUP_ID) ||
  0;

const SERVICE_SECRET =
  process.env.ROBLOX_REMOVE_SECRET ||
  process.env.RANK_SERVICE_SECRET ||
  process.env.SERVICE_SECRET;

const COOKIE = process.env.ROBLOSECURITY;

if (!COOKIE) { console.error("[fatal] ROBLOSECURITY not set"); process.exit(1); }
if (!GROUP_ID) { console.error("[fatal] ROBLOX_GROUP_ID (or GROUP_ID) not set/invalid"); process.exit(1); }
if (!SERVICE_SECRET) { console.error("[fatal] ROBLOX_REMOVE_SECRET (or SERVICE_SECRET/RANK_SERVICE_SECRET) not set"); process.exit(1); }

const app = express();
app.use(cors());
app.use(bodyParser.json());

let authed = false;

async function ensureAuth() {
  if (authed) return;
  await noblox.setCookie(COOKIE);
  const me = await noblox.getCurrentUser();
  if (!me?.UserID) throw new Error("Roblox auth sanity check failed");
  console.log(`[svc] Authenticated as ${me.UserName} (${me.UserID}) for group ${GROUP_ID}`);
  authed = true;
}

function isCsrfError(err) {
  const msg = String(err?.message || err || "");
  return /X-?CSRF/i.test(msg) || msg.includes("Did not receive X-CSRF-TOKEN");
}
const delay = (ms) => new Promise(r => setTimeout(r, ms));

async function withAuthRetry(fn, tries = 3) {
  for (let i = 1; i <= tries; i++) {
    try {
      await ensureAuth();
      return await fn();
    } catch (err) {
      console.error(`[svc] attempt ${i} failed:`, err?.message || err);
      if (isCsrfError(err) && i < tries) { authed = false; await delay(1500); continue; }
      throw err;
    }
  }
}

function requireSecret(req, res) {
  const got = req.get("X-Secret-Key");
  if (got !== SERVICE_SECRET) { res.status(401).json({ error: "unauthorized" }); return false; }
  return true;
}

// --- Routes ---

app.get("/health", async (_req, res) => {
  try { await ensureAuth(); res.json({ ok: true, groupId: GROUP_ID }); }
  catch (e) { res.status(500).json({ ok: false, error: String(e?.message || e) }); }
});

// Ranks for autocomplete
app.get("/ranks", async (req, res) => {
  if (!requireSecret(req, res)) return;
  try {
    const roles = await withAuthRetry(() => noblox.getRoles(GROUP_ID));
    // roles: [{id, name, rank}, ...]
    res.json({ roles });
  } catch (e) {
    console.error("[/ranks] error:", e?.message || e);
    res.status(500).json({ error: "ranks_failed" });
  }
});

// Set rank: accepts either { roleId } OR { rankNumber }
app.post("/set-rank", async (req, res) => {
  if (!requireSecret(req, res)) return;

  let { robloxId, roleId, rankNumber } = req.body || {};
  if (!robloxId) return res.status(400).json({ error: "missing_robloxId" });

  try {
    let rankToSet = null;

    if (roleId != null) {
      // Translate roleId -> rankNumber
      const roles = await withAuthRetry(() => noblox.getRoles(GROUP_ID));
      const role = roles.find(r => Number(r.id) === Number(roleId));
      if (!role) return res.status(400).json({ error: "invalid_roleId" });
      rankToSet = Number(role.rank);
    } else if (rankNumber != null) {
      rankToSet = Number(rankNumber);
    } else {
      return res.status(400).json({ error: "missing_roleId_or_rankNumber" });
    }

    // noblox expects rankNumber
    await withAuthRetry(() => noblox.setRank(GROUP_ID, Number(robloxId), rankToSet));
    res.json({ ok: true, appliedRank: rankToSet });
  } catch (e) {
    console.error("Set rank failed:", e?.message || e);
    res.status(500).json({ error: "set_rank_failed" });
  }
});

// Exile/remove from group
app.post("/remove", async (req, res) => {
  if (!requireSecret(req, res)) return;

  const { robloxId } = req.body || {};
  if (!robloxId) return res.status(400).json({ error: "missing_robloxId" });

  try {
    await withAuthRetry(() => noblox.exile(GROUP_ID, Number(robloxId)));
    res.json({ ok: true });
  } catch (e) {
    console.error("Remove (exile) failed:", e?.message || e);
    res.status(500).json({ error: "remove_failed" });
  }
});

app.listen(PORT, () => console.log(`Roblox service listening on :${PORT}`));
