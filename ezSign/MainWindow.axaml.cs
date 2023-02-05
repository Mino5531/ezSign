using Avalonia.Controls;
using Avalonia.Interactivity;
using System;
using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace ezSign
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            var viewModel = new ViewModel();
            viewModel.Status = "Ok";
            DataContext = viewModel;
            InitializeComponent();
        }

        public async void BrowseCertificate(object sender, RoutedEventArgs e)
        {
            OpenFileDialog fileDialog = new OpenFileDialog();
            fileDialog.Filters.Add(new FileDialogFilter() { Extensions = { "p12" }, Name = "PKCS12 File" });
            fileDialog.AllowMultiple = false;
            string[]? result = await fileDialog.ShowAsync(this);
            if (result == null)
            {
                return;
            }
            ((ViewModel)DataContext).CertificatePath = result[0];
        }

        public async void BrowseXML(object sender, RoutedEventArgs e)
        {
            OpenFileDialog fileDialog = new OpenFileDialog();
            fileDialog.Filters.Add(new FileDialogFilter() { Extensions = { "xml", "XML" }, Name = "XML File" });
            fileDialog.AllowMultiple = false;
            string[]? result = await fileDialog.ShowAsync(this);
            if (result == null)
            {
                return;
            }
            ((ViewModel)DataContext).XMLPath = result[0];
        }

        public async void SignXML(object sender, RoutedEventArgs e)
        {
            string? certificatePath = ((ViewModel)DataContext).CertificatePath;
            string? xmlPath = ((ViewModel)DataContext).XMLPath;
            if (string.IsNullOrEmpty(certificatePath))
            {
                ((ViewModel)DataContext).Status = "Error: No certificate set";
                return;
            }
            if (string.IsNullOrEmpty(xmlPath))
            {
                ((ViewModel)DataContext).Status = "Error: No xml file set";
                return;
            }
            try
            {
                X509Certificate2 signingCert = new X509Certificate2(certificatePath,
                    string.IsNullOrEmpty(((ViewModel)DataContext).Password) ? "" : ((ViewModel)DataContext).Password);
                if (!signingCert.HasPrivateKey)
                {
                    ((ViewModel)DataContext).Status = "Certificate doesn't have a private key";
                    return;
                }
                XmlDocument xmlDoc = new()
                {
                    PreserveWhitespace = true,
                };
                xmlDoc.Load(xmlPath);
                XmlNode? node = xmlDoc.SelectSingleNode("//Transaction");

                if (node == null)
                {
                    ((ViewModel)DataContext).Status = "Xml file syntax error";
                    return;
                }

                var signingNode = xmlDoc.CreateNode(XmlNodeType.Element, "SigningCertificate", null);

                StringBuilder builder = new();
                builder.AppendLine("-----BEGIN CERTIFICATE-----");
                builder.AppendLine(Convert.ToBase64String(signingCert.RawData, Base64FormattingOptions.InsertLineBreaks));
                builder.AppendLine("-----END CERTIFICATE-----");
                signingNode.InnerText = builder.ToString();

                node.AppendChild(signingNode);

                SignedXml signedXml = new(xmlDoc)
                {
                    SigningKey = signingCert.GetRSAPrivateKey()
                };
                Reference reference = new()
                {
                    Uri = ""
                };
                XmlDsigEnvelopedSignatureTransform env = new();
                reference.AddTransform(env);
                signedXml.AddReference(reference);
                signedXml.ComputeSignature();
                XmlElement xmlDigitalSignature = signedXml.GetXml();
                xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
                xmlDoc.Save(xmlPath);
                ((ViewModel)DataContext).Status = "Signing complete";
            }
            catch (Exception ex)
            {
                ((ViewModel)DataContext).Status = ex.Message;
            }
        }

        class ViewModel : ViewModelBase
        {
            private string? _certificatePath;
            public string? CertificatePath
            {
                get => _certificatePath;
                set { SetProperty(ref _certificatePath, value); }
            }
            private string? _xmlPath;
            public string? XMLPath
            {
                get => _xmlPath;
                set { SetProperty(ref _xmlPath, value); }
            }

            private string? _status;
            public string? Status
            {
                get => _status;
                set { SetProperty(ref _status, value); }
            }

            private string? _password;
            public string? Password
            {
                get => _password;
                set { SetProperty(ref _password, value); }
            }
        }
    }
}
