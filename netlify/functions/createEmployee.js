const admin = require('firebase-admin');

function initAdmin(){
  if(admin.apps.length) return admin.app();

  let serviceAccount = null;
  if(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64){
    const json = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, 'base64').toString('utf8');
    serviceAccount = JSON.parse(json);
  } else if(process.env.FIREBASE_SERVICE_ACCOUNT_JSON){
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
  } else if(process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY){
    serviceAccount = {
      project_id: process.env.FIREBASE_PROJECT_ID,
      client_email: process.env.FIREBASE_CLIENT_EMAIL,
      private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
    };
  }

  if(!serviceAccount){
    throw new Error('Missing Firebase Admin credentials');
  }

  return admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    projectId: serviceAccount.project_id || process.env.FIREBASE_PROJECT_ID || 'gestionalenoor-2fa61'
  });
}

function json(statusCode, body){
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'POST, OPTIONS'
    },
    body: JSON.stringify(body)
  };
}

function cleanRole(role){
  const allowed = ['owner','manager','warehouse','seller','supervisor'];
  return allowed.includes(role) ? role : 'seller';
}

function cleanExtraPermissions(input){
  const allowed = ['sell','viewProducts','manageProducts','viewStock','manageStock','viewDiscounts','manageDiscounts','viewOrders','cancelOrders','editPayment','createClosure','editClosure','viewRevenue','viewCosts','viewAccessLogs'];
  const out = {};
  if(input && typeof input === 'object'){
    for(const key of allowed){
      if(input[key] === true || input[key] === 1) out[key] = true;
    }
  }
  return out;
}

exports.handler = async (event) => {
  if(event.httpMethod === 'OPTIONS') return json(200, {ok:true});
  if(event.httpMethod !== 'POST') return json(405, {error:'Metodo non consentito'});

  try{
    initAdmin();
    const authHeader = event.headers.authorization || event.headers.Authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if(!token) return json(401, {error:'Token mancante'});

    const decoded = await admin.auth().verifyIdToken(token);
    const db = admin.firestore();
    const callerSnap = await db.collection('users').doc(decoded.uid).get();
    if(!callerSnap.exists) return json(403, {error:'Profilo Super Admin non trovato'});
    const caller = callerSnap.data() || {};
    if(caller.active === false) return json(403, {error:'Utente disattivato'});
    if(!['owner','manager'].includes(caller.role)) return json(403, {error:'Solo Owner/Admin può gestire dipendenti'});

    const body = JSON.parse(event.body || '{}');
    const action = body.action || 'create';
    if(action === 'delete'){
  const uid = String(body.uid || '').trim();

  if(!uid){
    return json(400,{error:'UID dipendente mancante'});
  }

  if(uid === decoded.uid){
    return json(400,{error:'Non puoi eliminare il tuo account'});
  }

  const targetDoc = await db.collection('users').doc(uid).get();

  if(targetDoc.exists){
    await db.collection('users').doc(uid).delete();
  }

  try{
    await admin.auth().deleteUser(uid);
  }catch(err){
    console.error('Delete auth user:', err);
  }

  await db.collection('activityLogs').add({
    type:'employee_deleted',
    actorUid:decoded.uid,
    actorEmail:decoded.email || caller.email || '',
    targetUid:uid,
    createdAt:admin.firestore.FieldValue.serverTimestamp()
  });

  return json(200,{
    ok:true,
    deleted:true
  });
}
    const name = String(body.name || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '').trim();
    const role = cleanRole(body.role);
    const active = body.active !== false;
    const hasExtraPermissions = Object.prototype.hasOwnProperty.call(body, 'extraPermissions');
    const incomingExtraPermissions = cleanExtraPermissions(body.extraPermissions || {});

    if(!name) return json(400, {error:'Nome dipendente mancante'});
    if(!email) return json(400, {error:'Email dipendente mancante'});
    if(action === 'create' && password.length < 6) return json(400, {error:'Password minima 6 caratteri'});

    let userRecord = null;

    if(action === 'create'){
      try{
        userRecord = await admin.auth().getUserByEmail(email);
        return json(409, {error:'Esiste già un utente Firebase con questa email'});
      }catch(e){
        if(e.code !== 'auth/user-not-found') throw e;
      }
      userRecord = await admin.auth().createUser({
        email,
        password,
        displayName: name,
        disabled: !active,
        emailVerified: false
      });
    } else {
      const uid = String(body.uid || '').trim();
      if(!uid) return json(400, {error:'UID dipendente mancante'});
      const update = {email, displayName:name, disabled: !active};
      if(password && password.length >= 6) update.password = password;
      userRecord = await admin.auth().updateUser(uid, update);
    }

    await admin.auth().setCustomUserClaims(userRecord.uid, {role, active});

    const existingSnap = await db.collection('users').doc(userRecord.uid).get();
    const existingData = existingSnap.exists ? (existingSnap.data() || {}) : {};
    const extraPermissions = hasExtraPermissions ? incomingExtraPermissions : (existingData.extraPermissions || {});

    const userDoc = {
      uid: userRecord.uid,
      name,
      email,
      role,
      extraPermissions,
      active,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedBy: decoded.uid,
      updatedByEmail: decoded.email || caller.email || ''
    };
    if(action === 'create'){
      userDoc.createdAt = admin.firestore.FieldValue.serverTimestamp();
      userDoc.createdBy = decoded.uid;
      userDoc.createdByEmail = decoded.email || caller.email || '';
    }

    await db.collection('users').doc(userRecord.uid).set(userDoc, {merge:true});
    await db.collection('activityLogs').add({
      type: action === 'create' ? 'employee_created' : 'employee_updated',
      actorUid: decoded.uid,
      actorEmail: decoded.email || caller.email || '',
      targetUid: userRecord.uid,
      targetEmail: email,
      targetName: name,
      role,
      extraPermissions,
      active,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdAtClient: new Date().toISOString()
    });

    return json(200, {
      ok:true,
      user: {
        uid: userRecord.uid,
        firebaseUid: userRecord.uid,
        name,
        email,
        role,
        extraPermissions,
        active
      }
    });
  }catch(error){
    console.error('createEmployee error:', error);
    let msg = error.message || 'Errore creazione dipendente';
    if(error.code === 'auth/email-already-exists') msg = 'Email già registrata in Firebase';
    if(error.code === 'auth/invalid-password') msg = 'Password non valida';
    return json(500, {error: msg});
  }
};
