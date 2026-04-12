const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Supabase ───────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── Middleware auth ────────────────────────────────────────────────
async function auth(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No autorizado' });

  const { data: sesion } = await supabase
    .from('sesiones')
    .select('*, usuarios(*)')
    .eq('token', token)
    .gt('expires_at', new Date().toISOString())
    .single();

  if (!sesion) return res.status(401).json({ error: 'Sesión expirada' });

  const { data: empresa } = await supabase
    .from('empresas')
    .select('*')
    .eq('id', sesion.usuarios.empresa_id)
    .single();

  if (!empresa?.activa && sesion.usuarios.rol !== 'superadmin') return res.status(403).json({ error: 'Empresa desactivada' });
  if (new Date(empresa.trial_fin) < new Date() && empresa.plan === 'trial' && sesion.usuarios.rol !== 'superadmin') {
    return res.status(403).json({ error: 'Trial expirado', trial_expirado: true });
  }

  req.usuario = sesion.usuarios;
  req.empresa = empresa;
  next();
}

function soloAdmin(req, res, next) {
  if (!['admin', 'superadmin'].includes(req.usuario.rol)) {
    return res.status(403).json({ error: 'Solo administradores' });
  }
  next();
}

// ══════════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════════

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email y contraseña requeridos' });

  const { data: usuario } = await supabase
    .from('usuarios')
    .select('*')
    .eq('email', email.toLowerCase())
    .eq('activo', true)
    .single();

  if (!usuario) return res.status(401).json({ error: 'Email o contraseña incorrectos' });

  const ok = await bcrypt.compare(password, usuario.password_hash);
  if (!ok) return res.status(401).json({ error: 'Email o contraseña incorrectos' });

  const { data: empresa } = await supabase
    .from('empresas')
    .select('*')
    .eq('id', usuario.empresa_id)
    .single();

  if (!empresa?.activa) return res.status(403).json({ error: 'Cuenta desactivada. Contacta con soporte.' });

  const diasRestantes = Math.ceil((new Date(empresa.trial_fin) - new Date()) / (1000 * 60 * 60 * 24));
  if (diasRestantes <= 0 && empresa.plan === 'trial') {
    return res.status(403).json({ error: 'Tu período de prueba ha finalizado. Contacta con soporte para continuar.', trial_expirado: true });
  }

  const token = uuidv4() + uuidv4();
  await supabase.from('sesiones').insert({ usuario_id: usuario.id, token });
  await supabase.from('usuarios').update({ ultimo_acceso: new Date() }).eq('id', usuario.id);

  res.json({
    token,
    usuario: { id: usuario.id, nombre: usuario.nombre, email: usuario.email, rol: usuario.rol },
    empresa: { id: empresa.id, nombre: empresa.nombre, plan: empresa.plan, dias_trial: diasRestantes > 0 ? diasRestantes : 0 }
  });
});

app.post('/api/logout', auth, async (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  await supabase.from('sesiones').delete().eq('token', token);
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  const dias = Math.ceil((new Date(req.empresa.trial_fin) - new Date()) / (1000 * 60 * 60 * 24));
  res.json({
    usuario: { id: req.usuario.id, nombre: req.usuario.nombre, email: req.usuario.email, rol: req.usuario.rol },
    empresa: { id: req.empresa.id, nombre: req.empresa.nombre, plan: req.empresa.plan, dias_trial: dias > 0 ? dias : 0 }
  });
});

// ══════════════════════════════════════════════════════════════════
// CLIENTES
// ══════════════════════════════════════════════════════════════════

app.get('/api/clientes', auth, async (req, res) => {
  let query = supabase
    .from('clientes')
    .select('*, usuarios(nombre)')
    .eq('empresa_id', req.empresa.id)
    .order('nombre');

  if (req.usuario.rol === 'comercial') {
    query = query.eq('comercial_id', req.usuario.id);
  }

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/clientes', auth, async (req, res) => {
  const cliente = {
    ...req.body,
    empresa_id: req.empresa.id,
    comercial_id: req.body.comercial_id || req.usuario.id
  };
  const { data, error } = await supabase.from('clientes').insert(cliente).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/clientes/:id', auth, async (req, res) => {
  const { id } = req.params;
  const { data: existing } = await supabase.from('clientes').select('*').eq('id', id).eq('empresa_id', req.empresa.id).single();
  if (!existing) return res.status(404).json({ error: 'Cliente no encontrado' });
  if (req.usuario.rol === 'comercial' && existing.comercial_id !== req.usuario.id) {
    return res.status(403).json({ error: 'No tienes permiso para editar este cliente' });
  }
  const { data, error } = await supabase.from('clientes').update({ ...req.body, updated_at: new Date() }).eq('id', id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/clientes/:id', auth, soloAdmin, async (req, res) => {
  const { id } = req.params;
  await supabase.from('clientes').delete().eq('id', id).eq('empresa_id', req.empresa.id);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════
// DOCUMENTOS (Supabase Storage)
// ══════════════════════════════════════════════════════════════════

app.get('/api/clientes/:id/documentos', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('documentos')
    .select('id, nombre, tipo, storage_path, created_at')
    .eq('cliente_id', req.params.id)
    .eq('empresa_id', req.empresa.id);
  if (error) return res.status(500).json({ error: error.message });

  // Generar URLs firmadas para cada documento
  const docs = await Promise.all((data || []).map(async doc => {
    if (doc.storage_path) {
      const { data: urlData } = await supabase.storage
        .from('documentos')
        .createSignedUrl(doc.storage_path, 3600); // 1 hora
      return { ...doc, url: urlData?.signedUrl || null };
    }
    return doc;
  }));
  res.json(docs);
});

app.post('/api/clientes/:id/documentos', auth, async (req, res) => {
  const { nombre, tipo, datos } = req.body;
  
  // Subir archivo a Storage
  const base64 = datos.split(',')[1] || datos;
  const buffer = Buffer.from(base64, 'base64');
  const ext = nombre.split('.').pop() || 'pdf';
  const storagePath = `${req.empresa.id}/${req.params.id}/${Date.now()}_${nombre}`;
  
  const { error: uploadError } = await supabase.storage
    .from('documentos')
    .upload(storagePath, buffer, { contentType: tipo, upsert: false });
  
  if (uploadError) return res.status(500).json({ error: uploadError.message });

  // Guardar referencia en BD
  const { data, error } = await supabase.from('documentos').insert({
    cliente_id: req.params.id,
    empresa_id: req.empresa.id,
    nombre,
    tipo,
    storage_path: storagePath
  }).select('id, nombre, tipo, storage_path, created_at').single();
  
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/documentos/:id', auth, async (req, res) => {
  const { data, error } = await supabase.from('documentos').select('*').eq('id', req.params.id).eq('empresa_id', req.empresa.id).single();
  if (error || !data) return res.status(404).json({ error: 'No encontrado' });
  
  if (data.storage_path) {
    const { data: urlData } = await supabase.storage
      .from('documentos')
      .createSignedUrl(data.storage_path, 3600);
    return res.json({ ...data, url: urlData?.signedUrl || null });
  }
  res.json(data);
});

app.delete('/api/documentos/:id', auth, async (req, res) => {
  const { data } = await supabase.from('documentos').select('storage_path').eq('id', req.params.id).eq('empresa_id', req.empresa.id).single();
  
  // Eliminar del Storage
  if (data?.storage_path) {
    await supabase.storage.from('documentos').remove([data.storage_path]);
  }
  
  await supabase.from('documentos').delete().eq('id', req.params.id).eq('empresa_id', req.empresa.id);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════
// USUARIOS (solo admin)
// ══════════════════════════════════════════════════════════════════

app.get('/api/usuarios', auth, soloAdmin, async (req, res) => {
  let query = supabase
    .from('usuarios')
    .select('id, nombre, email, rol, activo, ultimo_acceso, created_at')
    .eq('empresa_id', req.empresa.id)
    .order('nombre');
  // Si piden solo activos (para selectores de comerciales)
  if (req.query.activos === 'true') query = query.eq('activo', true);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/usuarios', auth, soloAdmin, async (req, res) => {
  const { nombre, email, password, rol } = req.body;
  if (!nombre || !email || !password) return res.status(400).json({ error: 'Faltan campos' });

  // ── LÍMITE: solo 1 admin por empresa ──────────────────────────
  if (rol === 'admin') {
    const { data: adminsExistentes } = await supabase
      .from('usuarios')
      .select('id')
      .eq('empresa_id', req.empresa.id)
      .eq('rol', 'admin')
      .eq('activo', true);
    if (adminsExistentes && adminsExistentes.length >= 1) {
      return res.status(400).json({ error: 'Solo se permite 1 administrador por empresa. Contacta con soporte para ampliar.' });
    }
  }

  const password_hash = await bcrypt.hash(password, 10);
  const { data, error } = await supabase.from('usuarios').insert({
    nombre, email: email.toLowerCase(), password_hash,
    rol: rol || 'comercial', empresa_id: req.empresa.id
  }).select('id, nombre, email, rol, activo').single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/usuarios/:id', auth, soloAdmin, async (req, res) => {
  const updates = { ...req.body };
  if (updates.password) {
    updates.password_hash = await bcrypt.hash(updates.password, 10);
    delete updates.password;
  }
  delete updates.empresa_id;
  const { data, error } = await supabase.from('usuarios').update(updates).eq('id', req.params.id).eq('empresa_id', req.empresa.id).select('id, nombre, email, rol, activo').single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/usuarios/:id', auth, soloAdmin, async (req, res) => {
  if (req.params.id === req.usuario.id) return res.status(400).json({ error: 'No puedes eliminarte a ti mismo' });
  await supabase.from('usuarios').update({ activo: false }).eq('id', req.params.id).eq('empresa_id', req.empresa.id);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════
// SUPERADMIN
// ══════════════════════════════════════════════════════════════════

function soloSuperAdmin(req, res, next) {
  if (req.usuario.rol !== 'superadmin') return res.status(403).json({ error: 'Acceso denegado' });
  next();
}

app.get('/api/admin/empresas', auth, soloSuperAdmin, async (req, res) => {
  const { data, error } = await supabase.from('empresas').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });

  // Añadir conteo de clientes por empresa
  const empresasConClientes = await Promise.all((data || []).map(async emp => {
    const { count } = await supabase.from('clientes').select('*', { count: 'exact', head: true }).eq('empresa_id', emp.id);
    return { ...emp, num_clientes: count || 0 };
  }));

  res.json(empresasConClientes);
});

app.post('/api/admin/empresas', auth, soloSuperAdmin, async (req, res) => {
  const { nombre, email, telefono, admin_nombre, admin_email, admin_password, plan, dias_trial } = req.body;

  const trial_fin = new Date();
  if ((plan || 'trial') === 'anual') trial_fin.setFullYear(trial_fin.getFullYear() + 1);
  else trial_fin.setDate(trial_fin.getDate() + (dias_trial || 30));

  const { data: empresa, error: e1 } = await supabase.from('empresas').insert({
    nombre, email, telefono, plan: plan || 'trial', trial_fin
  }).select().single();
  if (e1) return res.status(500).json({ error: e1.message });

  const password_hash = await bcrypt.hash(admin_password, 10);
  const { data: usuario, error: e2 } = await supabase.from('usuarios').insert({
    empresa_id: empresa.id, nombre: admin_nombre,
    email: admin_email.toLowerCase(), password_hash, rol: 'admin'
  }).select('id, nombre, email, rol').single();
  if (e2) return res.status(500).json({ error: e2.message });

  res.json({ empresa, usuario });
});

app.put('/api/admin/empresas/:id', auth, soloSuperAdmin, async (req, res) => {
  const { data, error } = await supabase.from('empresas').update(req.body).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ══════════════════════════════════════════════════════════════════
// LOGO EMPRESA
// ══════════════════════════════════════════════════════════════════

app.post('/api/empresa/logo', auth, soloAdmin, async (req, res) => {
  try {
    const { nombre, tipo, datos } = req.body;
    console.log('LOGO UPLOAD - empresa:', req.empresa.id, 'archivo:', nombre);
    const base64 = datos.split(',')[1] || datos;
    const buffer = Buffer.from(base64, 'base64');
    const ext = nombre.split('.').pop() || 'png';
    const storagePath = `logos/${req.empresa.id}/logo.${ext}`;
    console.log('LOGO UPLOAD - path:', storagePath, 'size:', buffer.length);

    const { data: uploadData, error: uploadError } = await supabase.storage
      .from('documentos')
      .upload(storagePath, buffer, { contentType: tipo, upsert: true });

    console.log('LOGO UPLOAD - result:', JSON.stringify(uploadData), 'error:', JSON.stringify(uploadError));
    if (uploadError) return res.status(500).json({ error: uploadError.message });

    const { data: urlData, error: urlError } = await supabase.storage
      .from('documentos')
      .createSignedUrl(storagePath, 60 * 60 * 24 * 365);

    console.log('LOGO URL - result:', urlData?.signedUrl ? 'OK' : 'NULL', 'error:', JSON.stringify(urlError));
    const url = urlData?.signedUrl || null;

    const { error: dbError } = await supabase.from('empresas').update({ logo_url: storagePath }).eq('id', req.empresa.id);
    console.log('LOGO DB - error:', JSON.stringify(dbError));

    res.json({ url });
  } catch(e) {
    console.error('LOGO ERROR:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/empresa/logo', auth, async (req, res) => {
  const { data: empresa } = await supabase
    .from('empresas')
    .select('logo_url')
    .eq('id', req.empresa.id)
    .single();

  if (!empresa?.logo_url) return res.json({ url: null });

  const { data: urlData } = await supabase.storage
    .from('documentos')
    .createSignedUrl(empresa.logo_url, 60 * 60 * 24 * 365);

  res.json({ url: urlData?.signedUrl || null });
});

// ══════════════════════════════════════════════════════════════════
// DASHBOARD
// ══════════════════════════════════════════════════════════════════

app.get('/api/dashboard', auth, async (req, res) => {
  let query = supabase.from('clientes').select('*').eq('empresa_id', req.empresa.id);
  if (req.usuario.rol === 'comercial') query = query.eq('comercial_id', req.usuario.id);

  const { data: clientes } = await query;
  if (!clientes) return res.json({});

  const hoy = new Date();
  const en30 = new Date(hoy); en30.setDate(hoy.getDate() + 30);
  const en90 = new Date(hoy); en90.setDate(hoy.getDate() + 90);

  const stats = {
    total: clientes.length,
    activos: clientes.filter(c => c.estado === 'activo').length,
    incidencias: clientes.filter(c => c.estado === 'incidencia').length,
    bajas: clientes.filter(c => c.estado === 'baja').length,
    luz: clientes.filter(c => c.tipo === 'luz' || c.tipo === 'ambos').length,
    gas: clientes.filter(c => c.tipo === 'gas' || c.tipo === 'ambos').length,
    urgentes: clientes.filter(c => {
      const v = c.vencimiento_luz || c.vencimiento_gas;
      return v && new Date(v) <= en30 && new Date(v) >= hoy;
    }).length,
    alertas: clientes.filter(c => {
      const v = c.vencimiento_luz || c.vencimiento_gas;
      return v && new Date(v) > en30 && new Date(v) <= en90;
    }).length,
  };

  const { data: usuarios } = await supabase.from('usuarios')
    .select('id, nombre').eq('empresa_id', req.empresa.id).eq('activo', true);

  const comisiones = (usuarios || []).map(u => {
    const mis = clientes.filter(c => c.comercial_id === u.id);
    const total = mis.reduce((sum, c) => sum + (parseFloat(c.comision_importe) || 0), 0);
    return { nombre: u.nombre, total, clientes: mis.length };
  }).filter(u => u.clientes > 0).sort((a, b) => b.total - a.total);

  res.json({ stats, comisiones });
});

// ── Frontend ───────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`EnergyCRM server running on port ${PORT}`));
