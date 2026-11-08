import crypto from 'node:crypto';

function verifyTelegramInitData(initData, botToken) {
  const params = new URLSearchParams(initData);
  const hash = params.get('hash');

  if (!hash) return null;

  params.delete('hash');

  const authDate = Number(params.get('auth_date') || 0);
  const now = Math.floor(Date.now() / 1000);

  if (!authDate || authDate > now + 60 || now - authDate > 86400) {
    return null;
  }

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');

  const secretKey = crypto
    .createHmac('sha256', 'WebAppData')
    .update(botToken)
    .digest();

  const calculatedHash = crypto
    .createHmac('sha256', secretKey)
    .update(dataCheckString)
    .digest();

  let suppliedHash;

  try {
    suppliedHash = Buffer.from(hash, 'hex');
  } catch {
    return null;
  }

  if (
    suppliedHash.length !== calculatedHash.length ||
    !crypto.timingSafeEqual(suppliedHash, calculatedHash)
  ) {
    return null;
  }

  let user;

  try {
    user = JSON.parse(params.get('user') || 'null');
  } catch {
    return null;
  }

  if (!user?.id) return null;

  return user;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    return res.status(405).json({
      ok: false,
      error: 'Method not allowed'
    });
  }

  try {
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    const supabaseUrl = process.env.SUPABASE_URL;
    const supabaseKey = process.env.SUPABASE_SECRET_KEY;

    if (!botToken || !supabaseUrl || !supabaseKey) {
      throw new Error('Server environment variables are missing');
    }

    const initData = req.body?.initData;

    if (typeof initData !== 'string' || !initData) {
      return res.status(400).json({
        ok: false,
        error: 'Telegram initData is missing'
      });
    }

    const user = verifyTelegramInitData(initData, botToken);

    if (!user) {
      return res.status(401).json({
        ok: false,
        error: 'Telegram authentication failed'
      });
    }

    const response = await fetch(
      `${supabaseUrl.replace(/\/$/, '')}/rest/v1/players?on_conflict=telegram_id`,
      {
        method: 'POST',
        headers: {
          apikey: supabaseKey,
          Authorization: `Bearer ${supabaseKey}`,
          'Content-Type': 'application/json',
          Prefer: 'resolution=merge-duplicates,return=representation'
        },
        body: JSON.stringify({
          telegram_id: String(user.id),
          username: user.username || null,
          first_name: user.first_name || null,
          last_name: user.last_name || null,
          photo_url: user.photo_url || null
        })
      }
    );

    if (!response.ok) {
      const details = await response.text();
      console.error('Supabase players error:', response.status, details);

      return res.status(500).json({
        ok: false,
        error: 'Could not save player'
      });
    }

    const players = await response.json();

    return res.status(200).json({
      ok: true,
      player: players?.[0] || {
        telegram_id: String(user.id),
        username: user.username || null,
        first_name: user.first_name || null
      },
      balance: 0,
      inventory: []
    });

  } catch (error) {
    console.error('Telegram auth error:', error);

    return res.status(500).json({
      ok: false,
      error: 'Server authentication error'
    });
  }
}
