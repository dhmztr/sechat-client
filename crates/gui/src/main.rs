use iced::Element;
use iced::widget::text;
use iced::widget::{button, container, text_input};
use iced::widget::{column, row};
#[derive(Debug, Clone)]
enum Message {
    Login,
    PasswordChanged(String),
    Quit,
}
enum Screen {
    Register,
    Login,
    MainMenu,
    Chat { peer_id: String },
}

struct App {
    screen: Screen,
    password: String,
}
impl Default for App {
    fn default() -> Self {
        App {
            screen: Screen::Login,
            password: String::new(),
        }
    }
}
impl App {
    fn login_view(&self) -> Element<Message> {
        let input = text_input("Please provide password...", &self.password)
            .on_input(Message::PasswordChanged);
        let label = text("Please provide your password!");
        let login_button = button("Login").on_press_maybe(if !self.password.is_empty() {
            Some(Message::Login)
        } else {
            None
        });
        let quit_button = button("Quit app").on_press(Message::Quit);
        let rowik = row![login_button, quit_button];
        column![label, input, rowik].into()
    }
    fn view(&self) -> Element<Message> {
        match self.screen {
            Screen::Login => self.login_view(),
            Screen::MainMenu => self.main_menu_view(),
            _ => unreachable!(),
        }
    }
    fn main_menu_view(&self) -> Element<Message> {
        let mainlabel = text("ChatApp!");
        let quit_button = button("Quit app").on_press(Message::Quit);
        column![mainlabel, quit_button]
            .align_x(iced::alignment::Horizontal::Center)
            .padding(30)
            .into()
    }
    fn update(&mut self, message: Message) -> iced::Task<Message> {
        match message {
            Message::Login => {
                if self.password == "tajnehaslo" {
                    self.screen = Screen::MainMenu;
                    iced::Task::none()
                } else {
                    iced::Task::none()
                }
            }
            Message::PasswordChanged(s) => {
                self.password = s;
                iced::Task::none()
            }
            Message::Quit => return iced::exit(),
        }
    }
}

fn main() -> iced::Result {
    iced::run(App::update, App::view)
}
