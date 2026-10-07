// Fixture JS with INTENTIONAL flaws for Sentinel AI testing.
const { exec } = require("child_process");

function renderComment(comment) {
  // VULN: XSS via innerHTML
  document.getElementById("comment").innerHTML = comment;
}

function renderProfile(user) {
  // VULN: XSS via document.write
  document.write("<h1>" + user.name + "</h1>");
}

function calc(expr) {
  // VULN: eval
  return eval(expr);
}

function listDir(dir) {
  // VULN: command injection via template string
  exec(`ls -la ${dir}`, (err, stdout) => console.log(stdout));
}

const agent = require("https").Agent({ rejectUnauthorized: false }); // VULN: TLS off

module.exports = { renderComment, renderProfile, calc, listDir, agent };
