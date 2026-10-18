import * as vscode from 'vscode';
import * as fs from 'node:fs';

/** 等待 milliseconds 毫秒，让远程连接或终端完成异步工作。 */
function delay(milliseconds: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

/** 激活真实客户端验收；context 为 VS Code 提供的扩展上下文。 */
export function activate(context: vscode.ExtensionContext): void {
  void verify(context).catch(error => {
    const result = process.env.SSHDEV_E2E_RESULT;
    if (result) fs.writeFileSync(result, JSON.stringify({ok: false, error: String(error)}));
  });
}

/** 通过远程文件提供器、编辑器和集成终端验证 context 所在的 Remote SSH 窗口。 */
async function verify(context: vscode.ExtensionContext): Promise<void> {
  const result = process.env.SSHDEV_E2E_RESULT;
  if (!result) throw new Error('缺少验收结果路径');
  let folder: vscode.WorkspaceFolder | undefined;
  const deadline = Date.now() + 180_000;
  while (Date.now() < deadline) {
    folder = vscode.workspace.workspaceFolders?.[0];
    if (vscode.env.remoteName === 'ssh-remote' && folder?.uri.scheme === 'vscode-remote') break;
    await delay(200);
  }
  if (!folder || vscode.env.remoteName !== 'ssh-remote' || folder.uri.scheme !== 'vscode-remote') {
    throw new Error('没有打开真实 Remote SSH 工作区');
  }
  const file = vscode.Uri.joinPath(folder.uri, '编辑器 文件.txt');
  await vscode.workspace.fs.writeFile(file, Buffer.from('EDITOR_BEFORE'));
  const document = await vscode.workspace.openTextDocument(file);
  await vscode.window.showTextDocument(document);
  const edit = new vscode.WorkspaceEdit();
  edit.replace(file, new vscode.Range(document.positionAt(0), document.positionAt(document.getText().length)), 'EDITOR_AFTER');
  if (!await vscode.workspace.applyEdit(edit) || !await document.save()) throw new Error('远程编辑或保存失败');
  const text = Buffer.from(await vscode.workspace.fs.readFile(file)).toString('utf8');
  if (text !== 'EDITOR_AFTER') throw new Error('远程编辑结果不符');
  const marker = vscode.Uri.joinPath(folder.uri, 'terminal-marker.txt');
  const terminal = vscode.window.createTerminal({name: 'sshdev Remote SSH 验收'});
  context.subscriptions.push(terminal);
  terminal.show();
  terminal.sendText(`printf '%s' 'SSHDEV_TERMINAL_OK' > '${marker.fsPath.replace(/'/g, `'"'"'`)}'`);
  let terminalText = '';
  const terminalDeadline = Date.now() + 60_000;
  while (Date.now() < terminalDeadline) {
    try { terminalText = Buffer.from(await vscode.workspace.fs.readFile(marker)).toString('utf8'); } catch { /* 终端尚未生成标记。 */ }
    if (terminalText === 'SSHDEV_TERMINAL_OK') break;
    await delay(200);
  }
  if (terminalText !== 'SSHDEV_TERMINAL_OK') throw new Error('远程集成终端未执行命令');
  fs.writeFileSync(result, JSON.stringify({ok: true, remoteName: vscode.env.remoteName, uri: folder.uri.toString(), editorText: text, terminalMarker: terminalText}));
}
