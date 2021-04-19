using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Security.Cryptography;

namespace HashingMAC
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }
        private byte[] hash_bytes = null;
        byte[] key = null;

        private void CreateHMAC(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(plaintext_box.Text))
            {
                MessageBox.Show("Write some plaintext first");
                return;
            }

            if (generateKey.IsChecked == true)
            {
                key = new byte[20];
                using (var v = new RNGCryptoServiceProvider())
                {
                    v.GetBytes(key);
                    key_box.Text = Convert.ToBase64String(key);
                }
            }
            else
            {
                if (string.IsNullOrEmpty(key_box.Text))
                {
                    MessageBox.Show("Write a key first");
                    return;
                }
                key = Encoding.ASCII.GetBytes(key_box.Text);
            }

            var hash = HashAlgorithm.Create("hmac" + dropdown.Text);

            if (hash is HMAC hmac)
            {
                hmac.Key = key;
            }
            hash_bytes = hash.ComputeHash(Encoding.ASCII.GetBytes(plaintext_box.Text));
            // BitConverter converts the integers to 2 hextets, but it puts a hyphen between
            // each pair, so we just replace it with nothing
            MAC_hex_box.Text = BitConverter.ToString(hash_bytes).Replace("-", "");
            MAC_ascii_box.Text = Convert.ToBase64String(hash_bytes);
        }

        private bool IsBytesSame(byte[] bytes1, byte[] bytes2)
        {
            if (bytes1.Length != bytes2.Length)
            {
                return false;
            }
            for (int i = 0; i < bytes1.Length; i++)
            {
                if (bytes1[i] != bytes2[i])
                {
                    return false;
                }
            }
            return true;
        }

        private void VerifyMAC(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(plaintext_box.Text))
            {
                MessageBox.Show("Nothing to verify, write some plaintext");
                return;
            }

            if (generateKey.IsChecked == true)
            {
                if (key == null)
                {
                    MessageBox.Show("Key not generated");
                    return;
                }
            }
            else
            {
                if (string.IsNullOrEmpty(key_box.Text))
                {
                    MessageBox.Show("Cannot verify without key");
                    return;
                }
                key = Encoding.ASCII.GetBytes(key_box.Text);
            }

            var hash = HashAlgorithm.Create("hmac" + dropdown.Text);

            if (hash is HMAC hmac)
            {
                hmac.Key = key;
            }
            byte[] new_hash_bytes = hash.ComputeHash(Encoding.ASCII.GetBytes(plaintext_box.Text));
            if (IsBytesSame(hash_bytes, new_hash_bytes))
            {
                MessageBox.Show("HMAC verified");
            }
            else
            {
                MessageBox.Show("HMAC not verified, the hashes are not the same");
            }
        }
    }
}
