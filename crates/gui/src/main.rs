use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use client::{AppEvent, ChatLine, Client, Contact};
use iced::widget::{button, column, container, row, scrollable, space, text, text_input};
use iced::{Element, Length, Size, Subscription, Task, Theme, window};
use tokio::sync::mpsc::UnboundedReceiver;

const DEFAULT_SERVER: &str = "localhost:3000";
const EVENT_POLL_INTERVAL_MS: u64 = 200;
const KEY_LEN: usize = 32;
const SIDEBAR_WIDTH: f32 = 300.0;

type SharedReceiver = Arc<Mutex<Option<UnboundedReceiver<AppEvent>>>>;

fn main() -> iced::Result {
    iced::daemon(App::boot, App::update, App::view)
        .title(App::title)
        .theme(App::theme)
        .subscription(App::subscription)
        .run()
}

#[derive(Clone)]
enum Message {
    PasswordChanged(String),
    ServerChanged(String),
    SubmitPassword,
    Started(Result<(Client, SharedReceiver), String>),
    Tick,
    SelectPeer([u8; 32]),
    DraftChanged(String),
    SendDraft,
    AddPeerX25519Changed(String),
    AddPeerVerifyingChanged(String),
    AddPeer,
    ServerFieldChanged(String),
    ChangeServer,
    OpenSettings,
    ToggleTheme,
    AliasChanged(String),
    SetAlias,
    PurgeSelected,
    RemoveSelected,
    WindowClose(window::Id),
    DoExit,
    Ignored,
}

enum Screen {
    Unlock {
        password: String,
        server: String,
        error: Option<String>,
    },
    Main,
}

struct App {
    main_id: window::Id,
    settings_id: Option<window::Id>,
    dark: bool,
    screen: Screen,
    has_identity: bool,
    client: Option<Client>,
    rx: Option<UnboundedReceiver<AppEvent>>,
    contacts: Vec<Contact>,
    selected: Option<[u8; 32]>,
    history: Vec<ChatLine>,
    draft: String,
    status: String,
    add_x25519: String,
    add_verifying: String,
    server_field: String,
    my_keys: Option<(String, String)>,
    unread: HashMap<[u8; 32], usize>,
    alias_input: String,
    tick: u32,
}

impl App {
    fn boot() -> (Self, Task<Message>) {
        let (main_id, open) = window::open(window::Settings {
            size: Size::new(980.0, 660.0),
            min_size: Some(Size::new(720.0, 480.0)),
            ..window::Settings::default()
        });
        let app = Self {
            main_id,
            settings_id: None,
            dark: true,
            screen: Screen::Unlock {
                password: String::new(),
                server: client::resolve_server().unwrap_or_else(|| DEFAULT_SERVER.to_string()),
                error: None,
            },
            has_identity: client::identity_exists(),
            client: None,
            rx: None,
            contacts: Vec::new(),
            selected: None,
            history: Vec::new(),
            draft: String::new(),
            status: String::from("Not connected"),
            add_x25519: String::new(),
            add_verifying: String::new(),
            server_field: String::new(),
            my_keys: None,
            unread: HashMap::new(),
            alias_input: String::new(),
            tick: 0,
        };
        (app, open.map(|_| Message::Ignored))
    }

    fn title(&self, window: window::Id) -> String {
        if Some(window) == self.settings_id {
            String::from("SeChat — Settings")
        } else {
            String::from("SeChat")
        }
    }

    fn theme(&self, _window: window::Id) -> Theme {
        if self.dark {
            Theme::TokyoNight
        } else {
            Theme::Light
        }
    }

    fn subscription(&self) -> Subscription<Message> {
        let close = window::close_requests().map(Message::WindowClose);
        if self.rx.is_some() {
            let tick = iced::time::every(Duration::from_millis(EVENT_POLL_INTERVAL_MS))
                .map(|_| Message::Tick);
            Subscription::batch([tick, close])
        } else {
            close
        }
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::PasswordChanged(new_password) => {
                if let Screen::Unlock { password, .. } = &mut self.screen {
                    *password = new_password;
                }
                Task::none()
            }
            Message::ServerChanged(new_server) => {
                if let Screen::Unlock { server, .. } = &mut self.screen {
                    *server = new_server;
                }
                Task::none()
            }
            Message::SubmitPassword => self.submit_password(),
            Message::Started(result) => self.on_started(result),
            Message::Tick => {
                self.drain_events();
                self.tick = self.tick.wrapping_add(1);
                if self.tick % 5 == 0 {
                    self.refresh_contacts();
                }
                Task::none()
            }
            Message::SelectPeer(id) => {
                self.select_peer(id);
                Task::none()
            }
            Message::DraftChanged(draft) => {
                self.draft = draft;
                Task::none()
            }
            Message::SendDraft => {
                self.send_draft();
                Task::none()
            }
            Message::AddPeerX25519Changed(value) => {
                self.add_x25519 = value;
                Task::none()
            }
            Message::AddPeerVerifyingChanged(value) => {
                self.add_verifying = value;
                Task::none()
            }
            Message::AddPeer => {
                self.add_peer();
                Task::none()
            }
            Message::ServerFieldChanged(value) => {
                self.server_field = value;
                Task::none()
            }
            Message::ChangeServer => {
                self.change_server();
                Task::none()
            }
            Message::OpenSettings => {
                if self.settings_id.is_some() {
                    return Task::none();
                }
                let (id, open) = window::open(window::Settings {
                    size: Size::new(460.0, 640.0),
                    resizable: true,
                    ..window::Settings::default()
                });
                self.settings_id = Some(id);
                open.map(|_| Message::Ignored)
            }
            Message::ToggleTheme => {
                self.dark = !self.dark;
                Task::none()
            }
            Message::AliasChanged(value) => {
                self.alias_input = value;
                Task::none()
            }
            Message::SetAlias => {
                self.set_alias();
                Task::none()
            }
            Message::PurgeSelected => {
                if let (Some(client), Some(peer)) = (&self.client, self.selected) {
                    client.purge(peer);
                    self.history.clear();
                    self.status = String::from("Conversation purged");
                }
                Task::none()
            }
            Message::RemoveSelected => {
                if let (Some(client), Some(peer)) = (&self.client, self.selected) {
                    client.remove_peer(peer);
                    self.selected = None;
                    self.history.clear();
                    self.unread.remove(&peer);
                    self.status = format!("Removed {}", client::fingerprint(&peer));
                    self.refresh_contacts();
                }
                Task::none()
            }
            Message::WindowClose(id) => {
                if Some(id) == self.settings_id {
                    self.settings_id = None;
                    return window::close(id);
                }
                // Main window closed: shut down gracefully then exit.
                if let Some(client) = &self.client {
                    client.shutdown();
                }
                Task::perform(
                    async { tokio::time::sleep(Duration::from_millis(300)).await },
                    |_| Message::DoExit,
                )
            }
            Message::DoExit => iced::exit(),
            Message::Ignored => Task::none(),
        }
    }

    fn submit_password(&mut self) -> Task<Message> {
        let Screen::Unlock {
            password,
            server,
            error,
        } = &mut self.screen
        else {
            return Task::none();
        };
        if password.is_empty() {
            *error = Some(String::from("Password must not be empty"));
            return Task::none();
        }
        let server = {
            let trimmed = server.trim();
            if trimmed.is_empty() {
                DEFAULT_SERVER.to_string()
            } else {
                trimmed.to_string()
            }
        };
        let keys_result = if self.has_identity {
            client::unlock(password)
        } else {
            client::create_identity(password)
        };
        match keys_result {
            Ok(keys) => {
                *error = None;
                if let Err(e) = client::save_server(&server) {
                    *error = Some(format!("Failed to save server address: {e}"));
                    return Task::none();
                }
                self.server_field = server.clone();
                Task::perform(Client::start(keys, server), |result| {
                    Message::Started(
                        result
                            .map(|(client, rx)| {
                                (client, Arc::new(Mutex::new(Some(rx))) as SharedReceiver)
                            })
                            .map_err(|e| e.to_string()),
                    )
                })
            }
            Err(e) => {
                *error = Some(e.to_string());
                Task::none()
            }
        }
    }

    fn on_started(&mut self, result: Result<(Client, SharedReceiver), String>) -> Task<Message> {
        match result {
            Ok((client, shared_rx)) => {
                self.rx = shared_rx.lock().ok().and_then(|mut guard| guard.take());
                self.contacts = client.contacts();
                self.my_keys = Some(client.my_keys_hex());
                self.status = String::from("Connecting to server…");
                self.client = Some(client);
                self.screen = Screen::Main;
            }
            Err(e) => {
                let message = format!("Failed to start client: {e}");
                if let Screen::Unlock { error, .. } = &mut self.screen {
                    *error = Some(message);
                } else {
                    self.status = message;
                }
            }
        }
        Task::none()
    }

    fn drain_events(&mut self) {
        let mut events = Vec::new();
        if let Some(rx) = &mut self.rx {
            while let Ok(event) = rx.try_recv() {
                events.push(event);
            }
        }
        for event in events {
            self.apply_event(event);
        }
    }

    fn apply_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::Connected { observed_address } => {
                self.status = format!("Connected · seen as {observed_address}");
            }
            AppEvent::PeerOnline { .. } | AppEvent::PeerOffline { .. } => {
                self.refresh_contacts();
            }
            AppEvent::MessageArrived { peer, from_me } => {
                if self.selected == Some(peer) {
                    self.reload_history(peer);
                } else if !from_me {
                    *self.unread.entry(peer).or_insert(0) += 1;
                }
            }
            AppEvent::HolePunchDenied { peer, reason } => {
                self.status = format!(
                    "Hole punch denied by {}: {reason}",
                    client::fingerprint(&peer)
                );
            }
            AppEvent::SessionUp { peer, direct } => {
                self.status = format!(
                    "Connected to {} ({})",
                    client::fingerprint(&peer),
                    if direct { "direct P2P" } else { "relay" }
                );
            }
            AppEvent::SessionDown { .. } => {}
            AppEvent::ConnectRetrying {
                peer,
                attempt,
                delay_secs,
            } => {
                self.status = format!(
                    "Connecting to {}… (attempt {attempt}, next in {delay_secs}s)",
                    client::fingerprint(&peer)
                );
            }
            AppEvent::ConnectGaveUp { peer } => {
                self.status = format!(
                    "Could not reach {}; will retry when it comes online",
                    client::fingerprint(&peer)
                );
            }
            AppEvent::Disconnected => {
                self.status = String::from("Disconnected from server");
            }
            AppEvent::Error(e) => {
                self.status = format!("Error: {e}");
            }
        }
    }

    fn refresh_contacts(&mut self) {
        if let Some(client) = &self.client {
            self.contacts = client.contacts();
        }
    }

    fn reload_history(&mut self, peer: [u8; 32]) {
        if let Some(client) = &self.client {
            match client.history(&peer) {
                Ok(history) => self.history = history,
                Err(e) => self.status = format!("Failed to load history: {e}"),
            }
        }
    }

    fn select_peer(&mut self, id: [u8; 32]) {
        self.selected = Some(id);
        self.unread.remove(&id);
        self.alias_input = self
            .contacts
            .iter()
            .find(|c| c.id == id)
            .and_then(|c| c.alias.clone())
            .unwrap_or_default();
        if let Some(client) = &self.client {
            client.connect_peer(id);
        }
        self.reload_history(id);
    }

    fn set_alias(&mut self) {
        let (Some(client), Some(peer)) = (&self.client, self.selected) else {
            self.status = String::from("Select a peer first");
            return;
        };
        match client.set_alias(&peer, &self.alias_input) {
            Ok(()) => {
                self.status = format!("Alias set to '{}'", self.alias_input.trim());
                self.refresh_contacts();
            }
            Err(e) => self.status = format!("Alias failed: {e}"),
        }
    }

    fn send_draft(&mut self) {
        let content = self.draft.trim().to_string();
        if content.is_empty() {
            return;
        }
        let (Some(client), Some(peer)) = (&self.client, self.selected) else {
            return;
        };
        client.send_message(peer, content);
        self.draft.clear();
    }

    fn add_peer(&mut self) {
        let x25519 = match parse_key_hex(&self.add_x25519, "x25519") {
            Ok(key) => key,
            Err(e) => {
                self.status = e;
                return;
            }
        };
        let verifying = match parse_key_hex(&self.add_verifying, "verifying") {
            Ok(key) => key,
            Err(e) => {
                self.status = e;
                return;
            }
        };
        let Some(client) = &self.client else {
            self.status = String::from("Client not started yet");
            return;
        };
        match client.add_peer(x25519, verifying) {
            Ok(id) => {
                self.status = format!("Added peer {}", client::fingerprint(&id));
                self.add_x25519.clear();
                self.add_verifying.clear();
                self.refresh_contacts();
            }
            Err(e) => self.status = format!("Failed to add peer: {e}"),
        }
    }

    fn change_server(&mut self) {
        let addr = self.server_field.trim().to_string();
        if addr.is_empty() {
            self.status = String::from("Server address must not be empty");
            return;
        }
        let Some(client) = &self.client else {
            self.status = String::from("Client not started yet");
            return;
        };
        client.set_server(addr.clone());
        self.server_field = addr.clone();
        self.status = format!("Reconnecting to {addr}…");
    }

    // --- views ----------------------------------------------------------------

    fn view(&self, window: window::Id) -> Element<'_, Message> {
        if Some(window) == self.settings_id {
            return self.settings_view();
        }
        match &self.screen {
            Screen::Unlock {
                password,
                server,
                error,
            } => self.unlock_view(password, server, error.as_deref()),
            Screen::Main => self.main_view(),
        }
    }

    fn unlock_view<'a>(
        &self,
        password: &'a str,
        server: &'a str,
        error: Option<&'a str>,
    ) -> Element<'a, Message> {
        let (label, action) = if self.has_identity {
            ("Enter your password to unlock your identity", "Unlock")
        } else {
            (
                "Choose a password to create a new identity",
                "Create identity",
            )
        };
        let input = text_input("Password", password)
            .secure(true)
            .padding(11)
            .on_input(Message::PasswordChanged)
            .on_submit(Message::SubmitPassword);
        let server_input = text_input("Server address", server)
            .padding(11)
            .on_input(Message::ServerChanged)
            .on_submit(Message::SubmitPassword);
        let submit = button(text(action).size(15))
            .on_press(Message::SubmitPassword)
            .style(button::primary)
            .width(Length::Fill);
        let mut content = column![
            accent_text("SeChat", 34.0),
            text(label).size(14),
            input,
            text("Relay server").size(13),
            server_input,
            submit,
        ]
        .spacing(14)
        .max_width(360);
        if let Some(error) = error {
            content = content.push(danger_text(error));
        }
        let card = container(content).style(container::rounded_box).padding(30);
        container(card)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }

    fn main_view(&self) -> Element<'_, Message> {
        let panels = row![
            card(
                self.contacts_panel(),
                Length::Fixed(SIDEBAR_WIDTH),
                Length::Fill
            ),
            card(self.chat_panel(), Length::Fill, Length::Fill),
        ]
        .spacing(12)
        .height(Length::Fill);
        column![self.top_bar(), panels, self.status_bar()]
            .spacing(12)
            .padding(14)
            .into()
    }

    fn top_bar(&self) -> Element<'_, Message> {
        let me = self
            .client
            .as_ref()
            .map(|c| format!("you · {}", c.my_fingerprint()))
            .unwrap_or_default();
        let settings_btn = button(text("\u{2699} Settings").size(14))
            .on_press(Message::OpenSettings)
            .style(button::secondary);
        row![
            accent_text("SeChat", 24.0),
            text(me).size(13),
            space::horizontal(),
            settings_btn,
        ]
        .spacing(12)
        .align_y(iced::Alignment::Center)
        .into()
    }

    fn contacts_panel(&self) -> Element<'_, Message> {
        let mut list = column![].spacing(4);
        for contact in &self.contacts {
            let dot = if contact.online {
                "\u{1F7E2}"
            } else {
                "\u{26AA}"
            };
            let unread = self.unread.get(&contact.id).copied().unwrap_or(0);
            let label = if unread > 0 {
                format!("{dot}  {}   \u{1F535} {unread}", contact.label())
            } else {
                format!("{dot}  {}", contact.label())
            };
            let selected = self.selected == Some(contact.id);
            let style = if selected {
                button::primary
            } else {
                button::text
            };
            list = list.push(
                button(text(label).size(14))
                    .on_press(Message::SelectPeer(contact.id))
                    .width(Length::Fill)
                    .style(style),
            );
        }
        let contacts_list = scrollable(list).height(Length::Fill);
        column![heading("Contacts"), contacts_list, self.add_peer_area()]
            .spacing(12)
            .width(Length::Fill)
            .into()
    }

    fn add_peer_area(&self) -> Element<'_, Message> {
        let x25519_input = text_input("x25519 public key (hex)", &self.add_x25519)
            .on_input(Message::AddPeerX25519Changed)
            .padding(8)
            .size(13);
        let verifying_input = text_input("ed25519 verifying key (hex)", &self.add_verifying)
            .on_input(Message::AddPeerVerifyingChanged)
            .padding(8)
            .size(13);
        let add_button = button(text("Add peer").size(14))
            .on_press(Message::AddPeer)
            .style(button::primary)
            .width(Length::Fill);
        column![
            text("Add a peer").size(15),
            x25519_input,
            verifying_input,
            add_button
        ]
        .spacing(6)
        .into()
    }

    fn chat_panel(&self) -> Element<'_, Message> {
        let Some(selected) = self.selected else {
            return container(text("Select a contact to start chatting").size(15))
                .center_x(Length::Fill)
                .center_y(Length::Fill)
                .into();
        };
        let peer_name = self.peer_label(&selected);
        let mut messages = column![].spacing(6);
        for line in &self.history {
            messages = messages.push(message_bubble(line));
        }
        let conversation = scrollable(messages)
            .height(Length::Fill)
            .width(Length::Fill);
        let draft_input = text_input("Type a message…", &self.draft)
            .on_input(Message::DraftChanged)
            .on_submit(Message::SendDraft)
            .padding(10);
        let send_button = button(text("Send").size(14))
            .on_press(Message::SendDraft)
            .style(button::primary);
        let compose = row![draft_input, send_button]
            .spacing(8)
            .align_y(iced::Alignment::Center);
        let header = row![
            text(format!("Chat with {peer_name}"))
                .size(18)
                .width(Length::Fill)
                .style(|t: &Theme| text::Style {
                    color: Some(t.palette().primary),
                }),
            button(text("Purge").size(14))
                .on_press(Message::PurgeSelected)
                .style(button::secondary),
            button(text("Remove").size(14))
                .on_press(Message::RemoveSelected)
                .style(button::danger),
        ]
        .spacing(8)
        .align_y(iced::Alignment::Center);
        column![header, conversation, compose]
            .spacing(10)
            .width(Length::Fill)
            .into()
    }

    fn status_bar(&self) -> Element<'_, Message> {
        container(text(&self.status).size(13))
            .style(container::rounded_box)
            .padding([6, 12])
            .width(Length::Fill)
            .into()
    }

    // --- settings window ------------------------------------------------------

    fn settings_view(&self) -> Element<'_, Message> {
        let theme_btn = button(
            text(if self.dark {
                "\u{2600} Switch to light"
            } else {
                "\u{1F319} Switch to dark"
            })
            .size(14),
        )
        .on_press(Message::ToggleTheme)
        .style(button::secondary)
        .width(Length::Fill);

        let sections = column![
            heading("Settings"),
            section("Appearance", theme_btn.into()),
            section("Relay server", self.server_area()),
            section("Peer alias", self.alias_area()),
            section("Your keys", self.my_keys_area()),
            section(
                "Storage",
                text(format!("Data dir: {}", client::data_dir()))
                    .size(12)
                    .into()
            ),
        ]
        .spacing(16);

        container(scrollable(sections).height(Length::Fill))
            .padding(20)
            .into()
    }

    fn server_area(&self) -> Element<'_, Message> {
        let server_input = text_input("host:port", &self.server_field)
            .on_input(Message::ServerFieldChanged)
            .on_submit(Message::ChangeServer)
            .padding(9)
            .size(14);
        let change_button = button(text("Change").size(14))
            .on_press(Message::ChangeServer)
            .style(button::secondary);
        row![server_input, change_button]
            .spacing(8)
            .align_y(iced::Alignment::Center)
            .into()
    }

    fn alias_area(&self) -> Element<'_, Message> {
        let input = text_input("name for the selected peer", &self.alias_input)
            .on_input(Message::AliasChanged)
            .on_submit(Message::SetAlias)
            .padding(9)
            .size(14);
        row![
            input,
            button(text("Save").size(14))
                .on_press(Message::SetAlias)
                .style(button::secondary)
        ]
        .spacing(8)
        .align_y(iced::Alignment::Center)
        .into()
    }

    fn my_keys_area(&self) -> Element<'_, Message> {
        let Some((x25519_hex, verifying_hex)) = &self.my_keys else {
            return text("Unlock your identity to see your keys.")
                .size(13)
                .into();
        };
        let fingerprint = self
            .client
            .as_ref()
            .map(Client::my_fingerprint)
            .unwrap_or_default();
        let key_row = |label: &'static str, value: &str| {
            column![
                text(label).size(12),
                text_input("", value)
                    .on_input(|_| Message::Ignored)
                    .padding(7)
                    .size(12),
            ]
            .spacing(3)
        };
        column![
            text(format!("Fingerprint: {fingerprint}")).size(13),
            text("Share both keys so a peer can add you:").size(12),
            key_row("x25519", x25519_hex),
            key_row("ed25519 verifying", verifying_hex),
        ]
        .spacing(8)
        .into()
    }

    fn peer_label(&self, id: &[u8; 32]) -> String {
        self.contacts
            .iter()
            .find(|contact| &contact.id == id)
            .map(|contact| contact.label().to_string())
            .unwrap_or_else(|| client::fingerprint(id))
    }
}

// --- free helpers -------------------------------------------------------------

fn accent_text(label: &str, size: f32) -> Element<'static, Message> {
    text(label.to_string())
        .size(size)
        .style(|t: &Theme| text::Style {
            color: Some(t.palette().primary),
        })
        .into()
}

fn heading(label: &str) -> Element<'static, Message> {
    accent_text(label, 18.0)
}

fn danger_text(label: &str) -> Element<'static, Message> {
    text(label.to_string())
        .size(14)
        .style(|t: &Theme| text::Style {
            color: Some(t.palette().danger),
        })
        .into()
}

fn section<'a>(title: &str, body: Element<'a, Message>) -> Element<'a, Message> {
    let inner = column![text(title.to_string()).size(15), body].spacing(8);
    container(inner)
        .style(container::rounded_box)
        .padding(14)
        .width(Length::Fill)
        .into()
}

fn card<'a>(content: Element<'a, Message>, width: Length, height: Length) -> Element<'a, Message> {
    container(content)
        .style(container::rounded_box)
        .padding(14)
        .width(width)
        .height(height)
        .into()
}

fn message_bubble(line: &ChatLine) -> Element<'static, Message> {
    let from_me = line.from_me;
    let bubble = container(text(line.text.clone()).size(14))
        .padding(10)
        .max_width(440)
        .style(move |t: &Theme| {
            let ext = t.extended_palette();
            let base = container::rounded_box(t);
            if from_me {
                container::Style {
                    background: Some(ext.primary.strong.color.into()),
                    text_color: Some(ext.primary.strong.text),
                    ..base
                }
            } else {
                base
            }
        });
    if from_me {
        row![space::horizontal(), bubble].into()
    } else {
        row![bubble, space::horizontal()].into()
    }
}

fn parse_key_hex(input: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(input.trim()).map_err(|e| format!("Invalid {label} key hex: {e}"))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        format!(
            "{label} key must be {KEY_LEN} bytes, got {} bytes",
            bytes.len()
        )
    })
}
