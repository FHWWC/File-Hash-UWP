using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.ApplicationModel.Core;
using Windows.ApplicationModel.DataTransfer;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Globalization;
using Windows.Networking.BackgroundTransfer;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage;
using Windows.Storage.FileProperties;
using Windows.Storage.Pickers;
using Windows.Storage.Provider;
using Windows.Storage.Streams;
using Windows.System.UserProfile;
using Windows.UI;
using Windows.UI.Popups;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

// https://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x804 上介绍了“空白页”项模板

namespace 文件校验
{
    /// <summary>
    /// 可用于自身或导航至 Frame 内部的空白页。
    /// </summary>
    public sealed partial class MainPage : Page
    {
        public MainPage()
        {
            this.InitializeComponent();
        }


        HashAlgorithmProvider alg, alg2, alg3, alg4, alg5 = null;
        CryptographicHash hash, hash2, hash3, hash4, hash5 = null;
        List<string> hashresult = new List<string>();
        string filename = "";

        private async void SelectFileBtn_Click(object sender, RoutedEventArgs e)
        {
            var SelectFile = new FileOpenPicker();

            SelectFile.SuggestedStartLocation = PickerLocationId.Desktop;
            SelectFile.FileTypeFilter.Add("*");
            SelectFile.FileTypeFilter.Add(".iso");
            SelectFile.FileTypeFilter.Add(".esd");
            SelectFile.FileTypeFilter.Add(".wim");
            SelectFile.FileTypeFilter.Add(".cab");
            StorageFile storageFile = await SelectFile.PickSingleFileAsync();

            StartCheckFile(storageFile);
        }
        public async void StartCheckFile(StorageFile storageFile)
        {
            if (storageFile != null)
            {
                if (CB1.IsChecked == false && CB2.IsChecked == false && CB3.IsChecked == false && CB4.IsChecked == false && CB5.IsChecked == false && CB6.IsChecked == false)
                {
                    return;
                }
                SelectFileBtn.IsEnabled = false;
                SelectPanel.Visibility = (Visibility)1;

                var size = await storageFile.GetBasicPropertiesAsync();
                filename = storageFile.Name;
                CheckIfm.Text += "File Path:" + storageFile.Path + "\n" + "Filesize:" + size.Size + "\n" + "Last Edit:" + size.DateModified + "\n" + "File Created Time:" + storageFile.DateCreated + "\n\n";

                try
                {
                    CheckRing.Visibility = 0;
                    CheckRing.IsActive = true;

                    RingText.Text = DisplayCustomLang("校验中...", "校驗中...", "Checking...", "Проверяю...");
                    RingText.Foreground = new SolidColorBrush(Colors.Black);

                    alg = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Md5);
                    alg2 = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha1);
                    alg3 = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha256);
                    alg4 = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha384);
                    alg5 = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha512);

                    var stream = await storageFile.OpenStreamForReadAsync();
                    var inputStream = stream.AsInputStream();
                    uint capacity = 100000000;

                    Windows.Storage.Streams.Buffer buffer = new Windows.Storage.Streams.Buffer(capacity);

                    hash = alg.CreateHash();
                    hash2 = alg2.CreateHash();
                    hash3 = alg3.CreateHash();
                    hash4 = alg4.CreateHash();
                    hash5 = alg5.CreateHash();

                    while (true)
                    {
                        await inputStream.ReadAsync(buffer, capacity, InputStreamOptions.None);

                        if (buffer.Length > 0)
                        {
                            if (CB1.IsChecked == true)
                            {
                                hash.Append(buffer);
                            }
                            if (CB2.IsChecked == true)
                            {
                                hash2.Append(buffer);
                            }
                            if (CB3.IsChecked == true)
                            {
                                hash3.Append(buffer);
                            }
                            if (CB4.IsChecked == true)
                            {
                                hash4.Append(buffer);
                            }
                            if (CB5.IsChecked == true)
                            {
                                hash5.Append(buffer);
                            }

                        }
                        else
                            break;

                    }


                    if (size.Size <= 2100000000)
                    {
                        if (CB6.IsChecked == true)
                        {
                            byte[] result;
                            using (stream = await storageFile.OpenStreamForReadAsync())
                            {
                                var memoryStream = new MemoryStream();
                                stream.CopyTo(memoryStream);
                                result = memoryStream.ToArray();
                            }

                            int iCount = result.Length;
                            UInt32 crc = 0xFFFFFFFF;
                            for (int i = 0; i < iCount; i++)
                            {
                                crc = ((crc >> 8) & 0x00FFFFFF) ^ Crc32Table[(crc ^ result[i]) & 0xFF];
                            }
                            crc ^= 0xFFFFFFFF;

                            CheckResult.Text += "CRC32: " + crc.ToString("X") + "\n\n";
                        }
                    }


                    inputStream.Dispose();
                    stream.Dispose();


                    if (CB1.IsChecked == true)
                    {
                        string result = CryptographicBuffer.EncodeToHexString(hash.GetValueAndReset()).ToUpper();
                        CheckResult.Text += "MD5: " + result + "\n\n";
                    }
                    if (CB2.IsChecked == true)
                    {
                        string result = CryptographicBuffer.EncodeToHexString(hash2.GetValueAndReset()).ToUpper();
                        CheckResult.Text += "SHA1: " + result + "\n\n";
                    }
                    if (CB3.IsChecked == true)
                    {
                        string result = CryptographicBuffer.EncodeToHexString(hash3.GetValueAndReset()).ToUpper();
                        CheckResult.Text += "SHA256: " + result + "\n\n";
                    }
                    if (CB4.IsChecked == true)
                    {
                        string result = CryptographicBuffer.EncodeToHexString(hash4.GetValueAndReset()).ToUpper();
                        CheckResult.Text += "SHA384: " + result + "\n\n";
                    }
                    if (CB5.IsChecked == true)
                    {
                        string result = CryptographicBuffer.EncodeToHexString(hash5.GetValueAndReset()).ToUpper();
                        CheckResult.Text += "SHA512: " + result + "\n\n";
                    }

                    hashresult.Add(storageFile.Name + "\n" + CheckResult.Text);
                    CheckResult.Text += "\n\n\n\n";

                    RingText.Text = DisplayCustomLang("校验成功", "校驗成功", "Completed", "Завершено");
                    RingText.Foreground = new SolidColorBrush(Colors.Green);

                }
                catch (Exception)
                {
                    RingText.Text = DisplayCustomLang("校验失败,请重试", "校驗失敗,請重試", "An error has occurred, please try again later.", "Произошла ошибка. Повторите попытку позже.");
                    RingText.Foreground = new SolidColorBrush(Colors.Red);
                }

                CheckRing.Visibility = (Visibility)1;
                CheckRing.IsActive = false;

                SelectFileBtn.IsEnabled = true;
                SelectPanel.Visibility = 0;
            }
            else
            {
                RingText.Text = DisplayCustomLang("操作被取消", "操作被取消", "Canceled by you", "Отменено вами");
                RingText.Foreground = new SolidColorBrush(Colors.Black);
            }


            DropPanel.Visibility = 0;
        }

        private static UInt32[] Crc32Table = {
                                  0x00000000,0x77073096,0xEE0E612C,0x990951BA,
                                  0x076DC419,0x706AF48F,0xE963A535,0x9E6495A3,
                                  0x0EDB8832,0x79DCB8A4,0xE0D5E91E,0x97D2D988,
                                  0x09B64C2B,0x7EB17CBD,0xE7B82D07,0x90BF1D91,
                                  0x1DB71064,0x6AB020F2,0xF3B97148,0x84BE41DE,
                                  0x1ADAD47D,0x6DDDE4EB,0xF4D4B551,0x83D385C7,
                                  0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,
                                  0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,
                                  0x3B6E20C8,0x4C69105E,0xD56041E4,0xA2677172,
                                  0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,
                                  0x35B5A8FA,0x42B2986C,0xDBBBC9D6,0xACBCF940,
                                  0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,
                                  0x26D930AC,0x51DE003A,0xC8D75180,0xBFD06116,
                                  0x21B4F4B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,
                                  0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,
                                  0x2F6F7C87,0x58684C11,0xC1611DAB,0xB6662D3D,
                                  0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,
                                  0x71B18589,0x06B6B51F,0x9FBFE4A5,0xE8B8D433,
                                  0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,
                                  0x7F6A0DBB,0x086D3D2D,0x91646C97,0xE6635C01,
                                  0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,
                                  0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,
                                  0x65B0D9C6,0x12B7E950,0x8BBEB8EA,0xFCB9887C,
                                  0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,
                                  0x4DB26158,0x3AB551CE,0xA3BC0074,0xD4BB30E2,
                                  0x4ADFA541,0x3DD895D7,0xA4D1C46D,0xD3D6F4FB,
                                  0x4369E96A,0x346ED9FC,0xAD678846,0xDA60B8D0,
                                  0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,
                                  0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,
                                  0x5768B525,0x206F85B3,0xB966D409,0xCE61E49F,
                                  0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,
                                  0x59B33D17,0x2EB40D81,0xB7BD5C3B,0xC0BA6CAD,
                                  0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,
                                  0xEAD54739,0x9DD277AF,0x04DB2615,0x73DC1683,
                                  0xE3630B12,0x94643B84,0x0D6D6A3E,0x7A6A5AA8,
                                  0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,
                                  0xF00F9344,0x8708A3D2,0x1E01F268,0x6906C2FE,
                                  0xF762575D,0x806567CB,0x196C3671,0x6E6B06E7,
                                  0xFED41B76,0x89D32BE0,0x10DA7A5A,0x67DD4ACC,
                                  0xF9B9DF6F,0x8EBEEFF9,0x17B7BE43,0x60B08ED5,
                                  0xD6D6A3E8,0xA1D1937E,0x38D8C2C4,0x4FDFF252,
                                  0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,
                                  0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,
                                  0xDF60EFC3,0xA867DF55,0x316E8EEF,0x4669BE79,
                                  0xCB61B38C,0xBC66831A,0x256FD2A0,0x5268E236,
                                  0xCC0C7795,0xBB0B4703,0x220216B9,0x5505262F,
                                  0xC5BA3BBE,0xB2BD0B28,0x2BB45A92,0x5CB36A04,
                                  0xC2D7FFA7,0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,
                                  0x9B64C2B0,0xEC63F226,0x756AA39C,0x026D930A,
                                  0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,
                                  0x95BF4A82,0xE2B87A14,0x7BB12BAE,0x0CB61B38,
                                  0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,0x0BDBDF21,
                                  0x86D3D2D4,0xF1D4E242,0x68DDB3F8,0x1FDA836E,
                                  0x81BE16CD,0xF6B9265B,0x6FB077E1,0x18B74777,
                                  0x88085AE6,0xFF0F6A70,0x66063BCA,0x11010B5C,
                                  0x8F659EFF,0xF862AE69,0x616BFFD3,0x166CCF45,
                                  0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,
                                  0xA7672661,0xD06016F7,0x4969474D,0x3E6E77DB,
                                  0xAED16A4A,0xD9D65ADC,0x40DF0B66,0x37D83BF0,
                                  0xA9BCAE53,0xDEBB9EC5,0x47B2CF7F,0x30B5FFE9,
                                  0xBDBDF21C,0xCABAC28A,0x53B39330,0x24B4A3A6,
                                  0xBAD03605,0xCDD70693,0x54DE5729,0x23D967BF,
                                  0xB3667A2E,0xC4614AB8,0x5D681B02,0x2A6F2B94,
                                  0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D};

        private void CopyBtn_Click(object sender, RoutedEventArgs e)
        {
            DataPackage dataPackage = new DataPackage();
            dataPackage.SetText(CheckIfm.Text+ CheckResult.Text);
            Clipboard.SetContent(dataPackage);
        }

        private void ShareBtn_Click(object sender, RoutedEventArgs e)
        {
            if (CheckResult.Text == "")
            {
                Ifm.Text = DisplayCustomLang("分享失败，当前没有校验结果，请先校验", "分享失敗，當前沒有校驗結果，請先校驗", "Share Failed", "Поделиться не удалось");
            }
            else
            {
                DataTransferManager.ShowShareUI();
                DataTransferManager dataTransfer = DataTransferManager.GetForCurrentView();
                dataTransfer.DataRequested += DataTransfer_DataRequested;
            }
        }

        private void DataTransfer_DataRequested(DataTransferManager sender, DataRequestedEventArgs args)
        {
            var ShareContent = args.Request.GetDeferral();
            DataPackage dataPackage = args.Request.Data;
            dataPackage.SetText(CheckIfm.Text + CheckResult.Text);
            dataPackage.Properties.Title = "File Hash Result";
            ShareContent.Complete();

            Ifm.Text = DisplayCustomLang("已分享", "已分享", "Shared", "Поделиться успешно");
        }

        private async void SaveBtn_Click(object sender, RoutedEventArgs e)
        {
            if (CheckResult.Text == "")
            {
                Ifm.Text = DisplayCustomLang("保存失败，因为当前没有校验结果", "保存失敗，因為當前沒有校驗結果", "Failed to save to text file", "Не удалось сохранить в текстовый файл");
            }
            else
            {

                var SelectFile = new FileSavePicker();

                SelectFile.SuggestedStartLocation = PickerLocationId.Desktop;
                SelectFile.FileTypeChoices.Add("文本文档", new List<string>() { ".txt" });
                SelectFile.FileTypeChoices.Add("日志文件", new List<string>() { ".log" });
                SelectFile.SuggestedFileName = "Hash-Result -- " + DateTime.Now +" - "+ filename;
                StorageFile storageFile = await SelectFile.PickSaveFileAsync();

                if (storageFile != null)
                {
                    CachedFileManager.DeferUpdates(storageFile);

                    await FileIO.WriteTextAsync(storageFile, CheckIfm.Text + CheckResult.Text);

                    FileUpdateStatus status = await CachedFileManager.CompleteUpdatesAsync(storageFile);

                    if (status == FileUpdateStatus.Complete)
                    {
                        Ifm.Text = DisplayCustomLang("已保存,保存位置：", "已保存,保存位置：", "Saved, file location:", "Сохранено, расположение файла:") + storageFile.Name;
                    }
                    else
                    {
                        Ifm.Text = DisplayCustomLang("内部错误,请稍后重试", "內部錯誤,請稍後重試", "Sorry, internal error, please try again later", "Извините, внутренняя ошибка. Повторите попытку позже.");
                    }
                }
                else
                {
                    Ifm.Text = DisplayCustomLang("操作被取消", "操作被取消", "Canceled by you", "Отменено вами");
                }
            }
        }

        private async void VerifyBtn_Click(object sender, RoutedEventArgs e)
        {          
            if(VerifyResultTb.Text=="")
            {
                return;
            }
            if (VerifyResultTb.Text.Length != 8 && VerifyResultTb.Text.Length != 32 && VerifyResultTb.Text.Length != 40 && VerifyResultTb.Text.Length != 64 && VerifyResultTb.Text.Length != 96 && VerifyResultTb.Text.Length != 128)
            {
                VerifyResultTb.Text = DisplayCustomLang("输入的校验值长度不正确", "輸入的校驗值長度不正確", "The length of the entered value is incorrect", "Длина введенного значения неверна");
                return;
            }

            bool haveItem = false;
            foreach(var item in hashresult)
            {
                if(item.Contains(VerifyResultTb.Text))
                {
                    VerifyResult.Text = item;
                    haveItem = true;
                    break;
                }
            }
            if(haveItem)
            {
                await VerifyDialog.ShowAsync();
            }
            else
            {
                VerifyResultTb.Text = DisplayCustomLang("没有匹配到之前的校验结果", "沒有匹配到之前的校驗結果", "No result", "Нет результата");
            }

        }

        private void SettingDialog_PrimaryButtonClick(ContentDialog sender, ContentDialogButtonClickEventArgs args)
        {

        }

        private void DropPanel_DragOver(object sender, DragEventArgs e)
        {
            e.AcceptedOperation = DataPackageOperation.Copy;

            SelectFileBtn.Visibility = (Visibility)1;
            DropNotifi.Visibility = 0;
            DropPanel.Background = new SolidColorBrush(Colors.Gray);
        }

        private async void DropPanel_Drop(object sender, DragEventArgs e)
        {
            if (e.DataView.Contains(StandardDataFormats.StorageItems))
            {
                var items = await e.DataView.GetStorageItemsAsync();
                if (items.Count == 1)
                {
                    DropPanel.Visibility = (Visibility)1;

                    var storageFile = items[0] as StorageFile;
                    StartCheckFile(storageFile);
                }
                else
                {
                    await new MessageDialog(DisplayCustomLang("一次只能拖放一个文件！", "一次只能拖放一個文件！", "You can only drag and drop one file at a time!", "Вы можете перетаскивать только один файл за раз!")).ShowAsync();
                }
            }
            else
            {
                await new MessageDialog(DisplayCustomLang("操作失败，请重新拖动文件", "操作失敗，請重新拖動文件", "An error has occurred, please try again", "Произошла ошибка. Повторите попытку позже")).ShowAsync();
            }

            SelectFileBtn.Visibility = 0;
            DropNotifi.Visibility = (Visibility)1;
            DropPanel.Background = new SolidColorBrush(Colors.Transparent);
        }

        private void DropPanel_DragLeave(object sender, DragEventArgs e)
        {
            SelectFileBtn.Visibility = 0;
            DropNotifi.Visibility = (Visibility)1;
            DropPanel.Background = new SolidColorBrush(Colors.Transparent);
        }

        private void VerifyDialog_PrimaryButtonClick(ContentDialog sender, ContentDialogButtonClickEventArgs args)
        {

        }

        private async void SettingBtn_Click(object sender, RoutedEventArgs e)
        {
            await SettingDialog.ShowAsync();
        }

        private void ClearBtn_Click(object sender, RoutedEventArgs e)
        {
            CheckIfm.ClearValue(TextBox.TextProperty);
            CheckResult.ClearValue(TextBox.TextProperty);
            hashresult.Clear();
        }
        public string DisplayCustomLang(string cn,string tw,string en,string ru)
        {
            if(ApplicationLanguages.PrimaryLanguageOverride.Contains("zh-Hans")|| ApplicationLanguages.PrimaryLanguageOverride.Contains("zh-CN"))
            {
                return cn;
            }
            else if (ApplicationLanguages.PrimaryLanguageOverride.Contains("zh-Hant"))
            {
                return tw;
            }
            else if (ApplicationLanguages.PrimaryLanguageOverride == "en")
            {
                return en;
            }
            else if (ApplicationLanguages.PrimaryLanguageOverride == "ru")
            {
                return ru;
            }

            return en;
        }

        private void SaveLang_Click(object sender, RoutedEventArgs e)
        {
            RestartPanel.Visibility = 0;

            switch(LanguageCtrl.SelectedIndex)
            {
                case 0:
                    ApplicationLanguages.PrimaryLanguageOverride = GlobalizationPreferences.Languages[0];
                    break;
                case 1:
                    ApplicationLanguages.PrimaryLanguageOverride = "zh-Hans";
                    break;
                case 2:
                    ApplicationLanguages.PrimaryLanguageOverride = "zh-Hant";
                    break;
                case 3:
                    ApplicationLanguages.PrimaryLanguageOverride = "en";
                    break;
                case 4:
                    ApplicationLanguages.PrimaryLanguageOverride = "ru";
                    break;
            }

        }

        private async void RestartBtn_Click(object sender, RoutedEventArgs e)
        {
            RestartErr.Visibility = Visibility.Collapsed;
            LangRing.IsActive = true;
            LangRing.Visibility = Visibility.Visible;
            try
            {
                await RestartFunc();
            }
            catch (Exception)
            {
                RestartErr.Visibility = Visibility.Visible;
            }

            LangRing.IsActive = false;
            LangRing.Visibility = Visibility.Collapsed;
        }
        private async Task RestartFunc()
        {
            await CoreApplication.RequestRestartAsync(string.Empty);
        }

        private async void OnlineCheckBtn_Click(object sender, RoutedEventArgs e)
        {
            Error.Visibility = (Visibility)1;
            if (string.IsNullOrWhiteSpace(OnlineCheck.Text) || OnlineCheck.Text.Length != 40)
            {
                Error.Visibility = 0;
                return;
            }

            try
            {
                HttpResponseMessage responseMessage = await new HttpClient().GetAsync("https://sha1.rg-adguard.net/search.php?sha1=" + OnlineCheck.Text);
                string result = await responseMessage.Content.ReadAsStringAsync();
                if (result.Contains("Match for this amount found in the database!"))
                {
                    OnlineResult.Text = DisplayCustomLang("已成功从数据库匹配到结果！", "已成功從數據庫匹配到結果！", "The file was successfully matched!", "Файл был успешно сопоставлен!");
                }
                else
                {
                    OnlineResult.Text = DisplayCustomLang("未查找到结果", "未查找到結果", "No result", "Нет результата");
                }
            }
            catch(Exception)
            {
                OnlineResult.Text = DisplayCustomLang("网络异常", "網絡異常", "Internet connection error", "Ошибка интернет-соединения");
            }

        }

    }
}
