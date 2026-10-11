import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { EventEmitter } from 'node:events';
import { boundedGet, withDeadline } from '../server/security.mjs';

test('transport pins its validated IP, keeps hostname TLS, and does not follow redirects', async (t) => {
  let calls = 0;
  t.mock.method(https, 'request', (options, callback) => {
    calls++;
    assert.equal(options.hostname, 'example.com');
    assert.equal(options.servername, 'example.com');
    assert.equal(options.rejectUnauthorized, true);
    assert.equal(options.path, '/');
    options.lookup('example.com', {}, (error, address, family) => {
      assert.equal(error, null);
      assert.equal(address, '8.8.8.8');
      assert.equal(family, 4);
    });
    options.lookup('example.com', { all: true }, (error, addresses) => {
      assert.equal(error, null);
      assert.deepEqual(addresses, [{ address: '8.8.8.8', family: 4 }]);
    });
    const req = new EventEmitter();
    req.end = () =>
      queueMicrotask(() => {
        const res = new EventEmitter();
        res.statusCode = 302;
        res.headers = { location: 'http://169.254.169.254/' };
        res.socket = {
          getProtocol: () => 'TLSv1.3',
          getCipher: () => ({ name: 'fixture' }),
          getPeerCertificate: () => ({}),
        };
        callback(res);
        res.emit('data', Buffer.from('redirect'));
        res.emit('end');
        req.emit('close');
      });
    req.destroy = (error) => {
      req.emit('error', error);
      req.emit('close');
    };
    return req;
  });
  const response = await boundedGet('https://example.com', '/', {
    resolver: async () => [{ address: '8.8.8.8', family: 4 }],
  });
  assert.equal(response.status, 302);
  assert.equal(calls, 1);
  assert.equal(response.ip, '8.8.8.8');
});
test('no socket is created for private or mixed DNS responses', async (t) => {
  const request = t.mock.method(https, 'request', () => {
    throw new Error('Unexpected socket');
  });
  await assert.rejects(
    boundedGet('https://example.com', '/', {
      resolver: async () => [{ address: '127.0.0.1', family: 4 }],
    }),
    /blocked/,
  );
  assert.equal(request.mock.callCount(), 0);
});
test('response byte budget aborts the underlying request', async (t) => {
  let aborted = false;
  t.mock.method(https, 'request', (_options, callback) => {
    const req = new EventEmitter();
    req.end = () =>
      queueMicrotask(() => {
        const res = new EventEmitter();
        res.statusCode = 200;
        res.headers = {};
        res.socket = {};
        callback(res);
        res.emit('data', Buffer.alloc(64));
      });
    req.destroy = (error) => {
      aborted = true;
      req.emit('error', error);
      req.emit('close');
    };
    return req;
  });
  await assert.rejects(
    boundedGet('https://example.com', '/', {
      resolver: async () => [{ address: '8.8.8.8', family: 4 }],
      maxBytes: 32,
    }),
    /byte budget/,
  );
  assert.equal(aborted, true);
});
test('unresponsive operations have a wall-clock deadline', async () => {
  await assert.rejects(
    withDeadline(new Promise(() => {}), 5, 'Deadline reached'),
    /Deadline reached/,
  );
});
