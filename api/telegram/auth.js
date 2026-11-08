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
  ) return null;

  try {
    const user = JSON.parse(params.get('user') || 'null');
    return user?.id ? user : null;
  } catch {
    return null;
  }
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  try {
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    const supabaseUrl = process.env.SUPABASE_URL?.replace(/\/$/, '');
    const supabaseKey = process.env.SUPABASE_SECRET_KEY;

    if (!botToken || !supabaseUrl || !supabaseKey) {
      throw new Error('Server environment variables are missing');
    }

    const initData = req.body?.initData;
    if (typeof initData !== 'string' || !initData) {
      return res.status(400).json({ ok: false, error: 'Telegram initData is missing' });
    }

    const user = verifyTelegramInitData(initData, botToken);
    if (!user) {
      return res.status(401).json({ ok: false, error: 'Telegram authentication failed' });
    }

    const headers = {
      apikey: supabaseKey,
      Authorization: `Bearer ${supabaseKey}`,
      'Content-Type': 'application/json'
    };

    const playerResponse = await fetch(
      `${supabaseUrl}/rest/v1/players?on_conflict=telegram_id`,
      {
        method: 'POST',
        headers: {
          ...headers,
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

    if (!playerResponse.ok) {
      console.error('Player save error:', await playerResponse.text());
      throw new Error('Could not save player');
    }

    const players = await playerResponse.json();
    const playerId = String(user.id);

    const [walletResponse, inventoryResponse] = await Promise.all([
      fetch(
        `${supabaseUrl}/rest/v1/wallets?player_id=eq.${encodeURIComponent(playerId)}&select=coins`,
        { headers }
      ),
      fetch(
        `${supabaseUrl}/rest/v1/inventory?player_id=eq.${encodeURIComponent(playerId)}&select=*`,
        { headers }
      )
    ]);

    if (!walletResponse.ok || !inventoryResponse.ok) {
      console.error(
        'Player data error:',
        await walletResponse.text(),
        await inventoryResponse.text()
      );
      throw new Error('Could not load player data');
    }

    const wallets = await walletResponse.json();
    const inventory = await inventoryResponse.json();

    return res.status(200).json({
      ok: true,
      player: players?.[0] || { telegram_id: playerId },
      balance: Number(wallets?.[0]?.coins ?? 0),
      inventory: inventory || []
    });

  } catch (error) {
    console.error('Telegram auth error:', error);return res.status(500).json({
      ok: false,
      error: 'Server authentication error'
    });
  }
}
