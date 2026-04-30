// VULNERABLE: Using eval for deserialization
export function deserializeWithEval(userInput: string) {
  const obj = eval('(' + userInput + ')');
  return obj;
}

// VULNERABLE: Function constructor for code evaluation
export function deserializeWithFunction(userInput: string) {
  const evaluator = new Function('return ' + userInput);
  return evaluator();
}

// VULNERABLE: eval in express route
import express from 'express';
const app = express();

app.post('/api/script', (req, res) => {
  try {
    const result = eval(req.body);
    res.json({ result });
  } catch (e) {
    res.status(400).json({ error: 'Invalid script' });
  }
});

// VULNERABLE: Dynamic code execution
app.post('/api/execute', (req, res) => {
  const code = req.query.code as string;
  const fn = new Function(code);
  const result = fn();
  res.json({ result });
});

// SAFE: Use JSON.parse instead
export function safeDeserialize(userInput: string) {
  return JSON.parse(userInput);
}
