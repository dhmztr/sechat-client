use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use client::{AppEvent, ChatLine, Client, Contact};
use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::{Element, Length, Subscription, Task};
use tokio::sync::mpsc::UnboundedReceiver;

const DEFAULT_SERVER: &str = "localhost:3000";
const EVENT_POLL_INTERVAL_MS: u64 = 200;
const KEY_LEN: usize = 32;
const SIDEBAR_WIDTH: f32 = 320.0;
const KEY_LABEL_WIDTH: f32 = 70.0;

type SharedReceiver = Arc<Mutex<Option<UnboundedReceiver<AppEvent>>>>;

fn main() -> iced::Result {
    iced::application(App::new, App::update, App::view)
        .subscription(App::subscription)
        .exit_on_close_request(false)
        .title("SeChat")
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
    ToggleOptions,
    AliasChanged(String),
    SetAlias,
    PurgeSelected,
    WindowClose(iced::window::Id),
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
    options_open: bool,
    alias_input: String,
    tick: u32,
}

impl App {
    fn new() -> Self {
        Self {
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
            options_open: false,
            alias_input: String::new(),
            tick: 0,
        }
    }

    fn subscription(&self) -> Subscription<Message> {
        let close = iced::window::close_requests().map(Message::WindowClose);
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
            Message::WindowClose(_) => {
                if let Some(client) = &self.client {
                    client.shutdown();
                }
                return Task::perform(
                    async { tokio::time::sleep(Duration::from_millis(300)).await },
                    |_| Message::DoExit,
                );
            }
            Message::DoExit => return iced::exit(),
            Message::ToggleOptions => {
                self.options_open = !self.options_open;
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
                self.status = String::from("Connecting to server...");
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
                self.status = format!("Connected (observed address: {observed_address})");
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
                    "Session with {} up ({})",
                    client::fingerprint(&peer),
                    if direct { "direct P2P" } else { "relay" }
                );
            }
            AppEvent::SessionDown { .. } => {}
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
        self.status = format!("reconnecting to {addr}…");
    }

    fn view(&self) -> Element<'_, Message> {
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
        let input = text_input("Password...", password)
            .secure(true)
            .on_input(Message::PasswordChanged)
            .on_submit(Message::SubmitPassword);
        let server_input = text_input("Server address...", server)
            .on_input(Message::ServerChanged)
            .on_submit(Message::SubmitPassword);
        let submit = button(action).on_press(Message::SubmitPassword);
        let mut content = column![
            text(label),
            input,
            text("Relay server").size(14),
            server_input,
            submit
        ]
        .spacing(12)
        .max_width(400);
        if let Some(error) = error {
            content = content.push(text(error).size(14));
        }
        container(content)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }

    fn main_view(&self) -> Element<'_, Message> {
        let options_btn = button(if self.options_open {
            "Close options"
        } else {
            "\u{2699} Options"
        })
        .on_press(Message::ToggleOptions);
        let panels = row![self.contacts_panel(), self.chat_panel()]
            .spacing(10)
            .height(Length::Fill);
        let mut col = column![row![options_btn].spacing(8), panels];
        if self.options_open {
            col = col.push(self.options_panel());
        }
        col.push(self.status_bar()).spacing(6).padding(10).into()
    }

    fn options_panel(&self) -> Element<'_, Message> {
        column![
            text("Options").size(18),
            self.server_area(),
            self.alias_area(),
            self.my_keys_area(),
            text(format!("Data dir: {}", client::data_dir())).size(12),
        ]
        .spacing(6)
        .into()
    }

    fn alias_area(&self) -> Element<'_, Message> {
        let input = text_input("alias for the selected peer", &self.alias_input)
            .on_input(Message::AliasChanged)
            .on_submit(Message::SetAlias)
            .size(14);
        row![
            text("Alias").size(14).width(Length::Fixed(KEY_LABEL_WIDTH)),
            input,
            button("Save").on_press(Message::SetAlias)
        ]
        .spacing(8)
        .into()
    }

    fn server_area(&self) -> Element<'_, Message> {
        let server_input = text_input("Server address...", &self.server_field)
            .on_input(Message::ServerFieldChanged)
            .on_submit(Message::ChangeServer)
            .size(14);
        let change_button = button("Change").on_press(Message::ChangeServer);
        row![
            text("Server")
                .size(14)
                .width(Length::Fixed(KEY_LABEL_WIDTH)),
            server_input,
            change_button
        ]
        .spacing(8)
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
                format!("{dot} {}   \u{1F535} {unread}", contact.label())
            } else {
                format!("{dot} {}", contact.label())
            };
            list = list.push(
                button(text(label).size(14))
                    .on_press(Message::SelectPeer(contact.id))
                    .width(Length::Fill),
            );
        }
        let contacts_list = scrollable(list).height(Length::Fill);
        column![
            text("Contacts").size(18),
            contacts_list,
            self.add_peer_area()
        ]
        .spacing(10)
        .width(Length::Fixed(SIDEBAR_WIDTH))
        .into()
    }

    fn add_peer_area(&self) -> Element<'_, Message> {
        let x25519_input = text_input("x25519 public key (hex)", &self.add_x25519)
            .on_input(Message::AddPeerX25519Changed)
            .size(14);
        let verifying_input = text_input("ed25519 verifying key (hex)", &self.add_verifying)
            .on_input(Message::AddPeerVerifyingChanged)
            .size(14);
        let add_button = button("Add peer").on_press(Message::AddPeer);
        column![
            text("Add peer").size(16),
            x25519_input,
            verifying_input,
            add_button
        ]
        .spacing(6)
        .into()
    }

    fn chat_panel(&self) -> Element<'_, Message> {
        let Some(selected) = self.selected else {
            return container(text("Select a contact to start chatting"))
                .center_x(Length::Fill)
                .center_y(Length::Fill)
                .into();
        };
        let peer_name = self.peer_fingerprint(&selected);
        let mut messages = column![].spacing(4);
        for line in &self.history {
            let author = if line.from_me {
                "You"
            } else {
                peer_name.as_str()
            };
            messages = messages.push(text(format!("{author}: {}", line.text)).size(14));
        }
        let conversation = scrollable(messages)
            .height(Length::Fill)
            .width(Length::Fill);
        let draft_input = text_input("Type a message...", &self.draft)
            .on_input(Message::DraftChanged)
            .on_submit(Message::SendDraft);
        let send_button = button("Send").on_press(Message::SendDraft);
        let compose = row![draft_input, send_button].spacing(8);
        let header = row![
            text(format!("Chat with {peer_name}"))
                .size(18)
                .width(Length::Fill),
            button(text("Purge").size(14)).on_press(Message::PurgeSelected)
        ]
        .spacing(8);
        column![header, conversation, compose]
            .spacing(10)
            .width(Length::Fill)
            .into()
    }

    fn my_keys_area(&self) -> Element<'_, Message> {
        let Some((x25519_hex, verifying_hex)) = &self.my_keys else {
            return column![].into();
        };
        let fingerprint = self
            .client
            .as_ref()
            .map(Client::my_fingerprint)
            .unwrap_or_default();
        let key_row = |label: &'static str, value: &str| {
            row![
                text(label).size(12).width(Length::Fixed(KEY_LABEL_WIDTH)),
                text_input("", value)
                    .on_input(|_| Message::Ignored)
                    .size(12)
            ]
            .spacing(8)
        };
        column![
            text(format!(
                "My keys (share with peers) — fingerprint: {fingerprint}"
            ))
            .size(14),
            key_row("x25519", x25519_hex),
            key_row("verifying", verifying_hex)
        ]
        .spacing(4)
        .into()
    }

    fn status_bar(&self) -> Element<'_, Message> {
        let me = self
            .client
            .as_ref()
            .map(|client| format!("Me: {}", client.my_fingerprint()))
            .unwrap_or_else(|| String::from("Me: (not started)"));
        row![
            text(me).size(14),
            text(&self.status).size(14).width(Length::Fill)
        ]
        .spacing(20)
        .into()
    }

    fn peer_fingerprint(&self, id: &[u8; 32]) -> String {
        self.contacts
            .iter()
            .find(|contact| &contact.id == id)
            .map(|contact| contact.label().to_string())
            .unwrap_or_else(|| client::fingerprint(id))
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
