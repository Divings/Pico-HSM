Pico-HSM Custom Firmware – README (Power Management Edition)

このファームウェアは、Raspberry Pi Pico / Pico W 互換機を簡易ハードウェアセキュリティモジュール（HSM）
として動作させるオリジナル実装に対して、「電源管理（Sleep / Shutdown）」だけを追加したカスタム版です。


注意:一部互換機向けの変更があります。Rasberripi picoなどで利用する場合、同封のVhenges.txtを使いコードを書き換えてください

暗号処理部分（HMAC、keypart、UID 派生、SEED管理、XOR暗号処理など）は
オリジナルから一切変更していません。

【今回追加された機能（カスタム内容はここだけ）】

1. Sleep モード（軽スリープ）
   コマンド: {"cmd": "sleep"}

   ・LED 4回点滅
   ・machine.idle() を使用
   ・USB接続は維持されたまま
   ・次回コマンド受信時に復帰
   ・Pico を抜き差ししても再認識される
   ・作業を続ける可能性がある場合に利用

2. Shutdown モード（完全停止）
   コマンド: {"cmd": "shutdown"}

   ・LED 2回点滅
   ・machine.lightsleep() による深いスリープ
   ・USBデバイスとして切断される
   ・復帰には Pico の抜き差し（または再起動）が必要
   ・作業完了後の安全な取り外し用モード


【変更していない部分（元の Pico-HSM そのまま）】

以下の機能は一切改変していません:

・HMAC-SHA256（独自実装）
・MASTER_SEED の生成／保存（os.urandom を使用）
・UID + MASTER_SEED による KDF
・128bit AES keypart の提供
・XOR 暗号処理
・INFO コマンド
・通常 LED 挙動
・print による JSON 応答フォーマット


【対応コマンド一覧】

hmac       : Base64入力データの HMAC-SHA256 を返す（元機能）
keypart    : AES鍵用128bit keypart を返す（元機能）
info       : デバイス情報を返す（元機能）
sleep      : 軽スリープ（LED4回点滅、USB維持） ← 追加
shutdown   : 深スリープ（LED2回点滅、USB切断） ← 追加


【Sleep / Shutdown の動作イメージ】

Sleep:
・Pico は待機状態に入るが USB は残る
・次のコマンドで復帰可能
・連続利用に向く

Shutdown:
・完全終了し USB から消える
・安全に取り外す用途
・再利用時は Pico の抜き差しが必要
（使用する互換機によっては完全に終了しない可能性あり)

【バージョン】

Firmware Version: 1.5.0-CUSTOM-PM
(PM = Power Management)


【目的】

暗号機能を維持したまま、使い勝手を改善するため
Sleep（軽スリープ）と Shutdown（完全停止）の2つの電源管理モードを追加しました。

