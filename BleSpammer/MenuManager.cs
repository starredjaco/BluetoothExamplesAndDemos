using UsbBluetooth;
using static BleSpammer.SpamManager;

namespace BleSpammer
{

    class MenuManager
    {
        private const int MENU_TOP = 11;
        private const int MAX_MENU_ITEMS = 10;

        private Controller m_UsbBtDevice;

        private static MenuManager m_Instance = null;

        public static MenuManager Instance { get { if (m_Instance == null) m_Instance = new MenuManager(); return m_Instance; } }

        #region Device selection
        //-------------------------------------------------------------------------------------------------------------------------------
        public void SelectUsbDevice()
        {
            List<string> options = new List<string>(UsbBluetoothManager.ListControllers().Select((device, index) => $"{device}"));

            int choice;
            do
            {
                choice = ShowMenu(options.ToArray(), "Select Usb Device:");
                if (choice == options.Count) Exit();
                else
                {
                    m_UsbBtDevice = UsbBluetoothManager.ListControllers().ToArray()[choice];

                    bool failed = false;
                    try
                    {
                        m_UsbBtDevice.Open();
                        m_UsbBtDevice.Initialize();
                    }
                    catch (Exception e)
                    {
                        failed = true;
                    }

                    if (failed)
                    {
                        Console.SetCursorPosition(0, MENU_TOP - 1);
                        WriteLine($"[i] Opening device [FAIL] (Be sure you are using WinUSB driver)");
                        return;
                    }
                    else
                        SpamMenu();

                }
            } while (choice != options.Count - 1);
        }
        //-------------------------------------------------------------------------------------------------------------------------------
        #endregion

        #region Spam - Select | Start | Stop
        //-------------------------------------------------------------------------------------------------------------------------------
        private void SpamMenu()
        {
            List<string> options = new List<string>(Enum.GetNames(typeof(SpamTargetType)));
            int choice;
            do
            {
                choice = ShowMenu(options.ToArray(), "Select target:");
                if (choice == options.Count) Exit();
                StartSpam(choice);
            } while (choice != options.Count - 1);
        }
        //-------------------------------------------------------------------------------------------------------------------------------

        //-------------------------------------------------------------------------------------------------------------------------------
        private void StartSpam(int option)
        {

            m_UsbBtDevice.StartAdvertisement(SpamManager.Instance.Payload((SpamTargetType)option));
            Console.SetCursorPosition(0, MENU_TOP - 2);

            SpammingMenu($"Spamming {((SpamTargetType)option).ToString()}\r\n");
        }
        //-------------------------------------------------------------------------------------------------------------------------------

        //-------------------------------------------------------------------------------------------------------------------------------
        private void SpammingMenu(string title)
        {
            List<string> options = new List<string> { "Stop" };
            int choice;
            do
            {
                choice = ShowMenu(options.ToArray(), title);
                if (choice == options.Count) Exit();
                StopSpam();
            } while (choice != options.Count - 1);
        }
        //-------------------------------------------------------------------------------------------------------------------------------

        //-------------------------------------------------------------------------------------------------------------------------------
        private void StopSpam()
        {
            m_UsbBtDevice.StopAdvertisement();
            SpamMenu();
        }
        //-------------------------------------------------------------------------------------------------------------------------------
        #endregion

        #region Misc
        //-------------------------------------------------------------------------------------------------------------------------------
        int ShowMenu(string[] options, string title = "")
        {
            Array.Resize(ref options, options.Length + 1);
            options[options.Length - 1] = "[Exit]";

            int selected = 0, key;
            Console.SetCursorPosition(0, MENU_TOP - 2);
            if (!string.IsNullOrEmpty(title)) { WriteLine($"{title}"); WriteLine(string.Empty); }

            do
            {
                int i = 0;
                for (; i < options.Length; i++)
                {
                    Console.SetCursorPosition(0, MENU_TOP + i);
                    Write($"{(i == selected ? "> " : "  ")} {i + 1}) {options[i].PadRight(50, ' ')}");
                }
                ClearLines(i);
                key = Console.ReadKey(true).Key switch { ConsoleKey.UpArrow => -1, ConsoleKey.DownArrow => 1, ConsoleKey.Enter => 0, _ => 99 };
                selected = (selected + key + options.Length) % options.Length;
            } while (key != 0);
            return selected;
        }
        //-------------------------------------------------------------------------------------------------------------------------------

        private void Exit() { if (m_UsbBtDevice != null) m_UsbBtDevice.Close(); Environment.Exit(0); }

        private void ClearLines(int pos) { for (; pos < MAX_MENU_ITEMS; pos++) { Console.SetCursorPosition(0, MENU_TOP + pos); Write("".PadRight(50, ' ')); } }
        private void WriteLine(string text) { Write(text.PadRight(50, ' ') + "\r\n"); }
        private void Write(string text) { Console.Write(text.PadRight(50, ' ')); }
        #endregion
    }
}
