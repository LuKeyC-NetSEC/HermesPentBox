// HermesPentBox preload：安全暴露窗口控制（最小化/最大化/关闭）给 renderer
const { contextBridge, ipcRenderer } = require('electron')
contextBridge.exposeInMainWorld('pentbox', {
  win: (act) => ipcRenderer.send('win-control', act),
})
