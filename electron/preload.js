// HermesPentBox preload：安全暴露窗口控制（最小化/最大化/关闭）+ 项目保存对话框（选路径/文件名）给 renderer
const { contextBridge, ipcRenderer } = require('electron')
contextBridge.exposeInMainWorld('pentbox', {
  win: (act) => ipcRenderer.send('win-control', act),
  // 弹系统保存对话框：返回选中路径（用户取消返回 null）
  saveProjectDialog: (defaultPath) => ipcRenderer.invoke('save-project-dialog', defaultPath),
})
