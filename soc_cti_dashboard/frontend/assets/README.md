# assets

## kano.png — 值班人員頭像

放一張 `kano.png` 在這個資料夾，「值班人員」面板就會自動改用它，不需要改任何程式碼
（`upgradeDutyAvatar()` 會偵測；檔案不存在時使用內建的 SVG 頭像）。

- 建議正方形、至少 192×192，PNG 或 WebP（存成 `kano.png` 即可）
- 會以圓形裁切並靠上對齊（`object-position: top center`），所以人臉放在畫面上半部效果最好
- 檔案會隨 `frontend/` 一起部署到 Pages，路徑為 `/assets/kano.png`

檔案不存在時，瀏覽器主控台會出現一次 404 —— 那是偵測用的請求，屬正常。
