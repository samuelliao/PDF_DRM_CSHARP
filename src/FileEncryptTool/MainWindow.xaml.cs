using Microsoft.Win32;
using MoonPdfLib;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace FileEncryptTool
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            //txt_ExpiredDate.Value = DateTime.Now;
        }

        private void btn_Encrypt_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(txt_FilePath.Text))
            {
                MessageBox.Show("Pease select a file");
            }
            else if (File.Exists(txt_FilePath.Text))
            {
                byte[] content = File.ReadAllBytes(txt_FilePath.Text);
                string expiredDate = txt_ExpiredDate.Value.HasValue ? txt_ExpiredDate.Value.Value.ToString("yyyy/MM/dd HH:mm:ss") : string.Empty;
                int result = FileCache.WriteEncryptedFile(txt_FilePath.Text, content, content.Length, 0, txt_Password.Password, expiredDate, txt_OpenLimit.Value.Value);
                if (result == 0)
                {
                    MessageBox.Show("Success");
                }
                else
                {
                    MessageBox.Show("Fail");
                }
            }
            else
            {
                MessageBox.Show("Somethingh goes wrong.");
            }

        }

        private void btn_FileBrowser_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Multiselect = false;
            openFileDialog.Filter = "Pdf Files|*.pdf";
            if (openFileDialog.ShowDialog() == true)
            {
                txt_FilePath.Text = openFileDialog.FileName;
            }
        }
    }
}
