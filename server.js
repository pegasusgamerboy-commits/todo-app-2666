import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand, QueryCommand, UpdateCommand, DeleteCommand } from '@aws-sdk/lib-dynamodb';
import { CognitoIdentityProviderClient, SignUpCommand, ConfirmSignUpCommand, InitiateAuthCommand, GetUserCommand } from '@aws-sdk/client-cognito-identity-provider';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const REGION = process.env.AWS_REGION;
if (!REGION) {
  console.error('Missing AWS_REGION');
  process.exit(1);
}
const TABLE_NAME = process.env.TABLE_NAME;
if (!TABLE_NAME) {
  console.error('Missing TABLE_NAME');
  process.exit(1);
}
const COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID;
if (!COGNITO_CLIENT_ID) {
  console.error('Missing COGNITO_CLIENT_ID');
  process.exit(1);
}

const ddbClient = new DynamoDBClient({ region: REGION });
const db = DynamoDBDocumentClient.from(ddbClient);
const cognito = new CognitoIdentityProviderClient({ region: REGION });

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const pairs = header.split(';');
  const cookies = {};
  for (var i = 0; i < pairs.length; i++) {
    var part = pairs[i].trim();
    if (!part) continue;
    var eqIdx = part.indexOf('=');
    var key = part.substring(0, eqIdx);
    var val = part.substring(eqIdx + 1);
    cookies[key] = val;
  }
  return cookies;
}

async function requireUser(req, res, next) {
  try {
    var cookies = parseCookies(req);
    var token = cookies['at'];
    if (!token) {
      res.status(401).json({ error: 'Unauthenticated' });
      return;
    }
    var cmd = new GetUserCommand({ AccessToken: token });
    var data = await cognito.send(cmd);
    var email = '';
    var sub = '';
    for (var i = 0; i < data.UserAttributes.length; i++) {
      var attr = data.UserAttributes[i];
      if (attr.Name === 'email') email = attr.Value;
      if (attr.Name === 'sub') sub = attr.Value;
    }
    if (!sub) {
      res.status(401).json({ error: 'Invalid token' });
      return;
    }
    req.user = { sub: sub, email: email };
    next();
  } catch (err) {
    res.status(401).json({ error: 'Unauthenticated' });
  }
}

// Health
app.get('/health', function (req, res) {
  res.type('text').send('ok');
});

// Auth routes (no auth required)
app.post('/auth/signup', async function (req, res) {
  try {
    var email = req.body.email;
    var password = req.body.password;
    var cmd = new SignUpCommand({
      ClientId: COGNITO_CLIENT_ID,
      Username: email,
      Password: password,
      UserAttributes: [{ Name: 'email', Value: email }]
    });
    await cognito.send(cmd);
    res.json({ message: 'Signup successful, check email for code' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/auth/confirm', async function (req, res) {
  try {
    var email = req.body.email;
    var code = req.body.code;
    var cmd = new ConfirmSignUpCommand({
      ClientId: COGNITO_CLIENT_ID,
      Username: email,
      ConfirmationCode: code
    });
    await cognito.send(cmd);
    res.json({ message: 'User confirmed' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/auth/login', async function (req, res) {
  try {
    var email = req.body.email;
    var password = req.body.password;
    var cmd = new InitiateAuthCommand({
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: COGNITO_CLIENT_ID,
      AuthParameters: { USERNAME: email, PASSWORD: password }
    });
    var data = await cognito.send(cmd);
    if (!data.AuthenticationResult) {
      res.status(400).json({ error: 'Authentication failed' });
      return;
    }
    var token = data.AuthenticationResult.AccessToken;
    res.setHeader('Set-Cookie', 'at=' + token + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=3300');
    res.json({ message: 'Logged in' });
  } catch (err) {
    if (err.name === 'UserNotConfirmedException') {
      res.status(403).json({ code: 'NOT_CONFIRMED' });
    } else {
      res.status(400).json({ error: err.message });
    }
  }
});

app.post('/auth/logout', async function (req, res) {
  res.setHeader('Set-Cookie', 'at=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ message: 'Logged out' });
});

app.get('/auth/me', async function (req, res) {
  try {
    var cookies = parseCookies(req);
    var token = cookies['at'];
    if (!token) {
      res.status(401).json({ error: 'Unauthenticated' });
      return;
    }
    var cmd = new GetUserCommand({ AccessToken: token });
    var data = await cognito.send(cmd);
    var email = '';
    for (var i = 0; i < data.UserAttributes.length; i++) {
      var attr = data.UserAttributes[i];
      if (attr.Name === 'email') email = attr.Value;
    }
    res.json({ email: email });
  } catch (err) {
    res.status(401).json({ error: 'Unauthenticated' });
  }
});

// Todo routes (protected)
app.get('/todos', requireUser, async function (req, res) {
  try {
    var pk = 'USER#' + req.user.sub;
    var cmd = new QueryCommand({
      TableName: TABLE_NAME,
      KeyConditionExpression: 'pk = :pk',
      ExpressionAttributeValues: { ':pk': pk },
      ScanIndexForward: true
    });
    var data = await db.send(cmd);
    var items = data.Items.map(function (it) {
      return {
        id: it.sk.replace('TODO#', ''),
        content: it.content,
        completed: it.completed,
        createdAt: it.createdAt
      };
    });
    res.json(items);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/todos', requireUser, async function (req, res) {
  try {
    var content = req.body.content;
    if (!content) {
      res.status(400).json({ error: 'Content required' });
      return;
    }
    var id = randomUUID();
    var now = new Date().toISOString();
    var item = {
      pk: 'USER#' + req.user.sub,
      sk: 'TODO#' + id,
      content: content,
      completed: false,
      createdAt: now
    };
    var cmd = new PutCommand({ TableName: TABLE_NAME, Item: item });
    await db.send(cmd);
    res.status(201).json({ id: id, content: content, completed: false, createdAt: now });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/todos/:id', requireUser, async function (req, res) {
  try {
    var id = req.params.id;
    var updates = req.body; // may contain content and/or completed
    var expression = [];
    var values = {};
    var names = {};
    if (updates.content !== undefined) {
      expression.push('#c = :c');
      values[':c'] = updates.content;
      names['#c'] = 'content';
    }
    if (updates.completed !== undefined) {
      expression.push('#comp = :comp');
      values[':comp'] = updates.completed;
      names['#comp'] = 'completed';
    }
    if (expression.length === 0) {
      res.status(400).json({ error: 'No fields to update' });
      return;
    }
    var cmd = new UpdateCommand({
      TableName: TABLE_NAME,
      Key: { pk: 'USER#' + req.user.sub, sk: 'TODO#' + id },
      UpdateExpression: 'SET ' + expression.join(', '),
      ExpressionAttributeNames: names,
      ExpressionAttributeValues: values,
      ReturnValues: 'ALL_NEW'
    });
    var data = await db.send(cmd);
    var item = data.Attributes;
    res.json({
      id: id,
      content: item.content,
      completed: item.completed,
      createdAt: item.createdAt
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/todos/:id', requireUser, async function (req, res) {
  try {
    var id = req.params.id;
    var cmd = new DeleteCommand({
      TableName: TABLE_NAME,
      Key: { pk: 'USER#' + req.user.sub, sk: 'TODO#' + id }
    });
    await db.send(cmd);
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(3000, '0.0.0.0', function () {
  console.log('Server listening on port 3000');
});
