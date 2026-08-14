# assets

## kano.png — 值班人員頭像

放一張 `kano.png` 在這個資料夾，「值班人員」面板就會自動改用它，不需要改任何程式碼
（`upgradeDutyAvatar()` 會偵測；檔案不存在時使用內建的 SVG 頭像）。

- 建議正方形、至少 192×192，PNG 或 WebP（存成 `kano.png` 即可）
- 會以圓形裁切並靠上對齊（`object-position: top center`），所以人臉放在畫面上半部效果最好
- 檔案會隨 `frontend/` 一起部署到 Pages，路徑為 `/assets/kano.png`

面板只以 76 CSS px 顯示這張圖，所以請先縮圖再放進來——目前這張是 256×256（涵蓋到
3 倍 DPR）、45 KB。原始檔常常是上千像素、數百 KB，那些位元每個訪客都要下載卻看不到。
縮圖同時會去掉 EXIF；原圖若含相機或生成工具的中繼資料，Pages 是公開的。

    python3 -c "from PIL import Image; im=Image.open('原圖').convert('RGB').resize((256,256), Image.LANCZOS); \
    im.quantize(colors=256).save('kano.png', optimize=True)"

檔案不存在時，瀏覽器主控台會出現一次 404 —— 那是偵測用的請求，屬正常。
