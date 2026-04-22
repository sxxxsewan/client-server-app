from __future__ import annotations

import json
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

import requests

SERVER_URL = "http://127.0.0.1:5000"



class WhoisApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("WHOIS-клиент | КСПиСТ")
        self.geometry("900x650")
        self.resizable(True, True)
        self.configure(bg="#f0f4f8")

        self._build_ui()

    def _build_ui(self):
        # Заголовок
        header = tk.Frame(self, bg="#2c3e50", pady=10)
        header.pack(fill=tk.X)
        tk.Label(
            header, text="WHOIS — информация о владельце домена",
            fg="white", bg="#2c3e50", font=("Arial", 16, "bold")
        ).pack()

        # Строка ввода
        input_frame = tk.Frame(self, bg="#f0f4f8", pady=10, padx=15)
        input_frame.pack(fill=tk.X)

        tk.Label(input_frame, text="Доменное имя:", bg="#f0f4f8",
                 font=("Arial", 11)).pack(side=tk.LEFT)
        self.domain_var = tk.StringVar()
        entry = tk.Entry(input_frame, textvariable=self.domain_var,
                         font=("Consolas", 12), width=35)
        entry.pack(side=tk.LEFT, padx=8)
        entry.bind("<Return>", lambda _: self._start_search())

        self.search_btn = tk.Button(
            input_frame, text="Поиск", command=self._start_search,
            bg="#2980b9", fg="white", font=("Arial", 11, "bold"),
            relief=tk.FLAT, padx=12, cursor="hand2"
        )
        self.search_btn.pack(side=tk.LEFT)

        self.log_btn = tk.Button(
            input_frame, text="Лог запросов", command=self._load_logs,
            bg="#27ae60", fg="white", font=("Arial", 11),
            relief=tk.FLAT, padx=12, cursor="hand2"
        )
        self.log_btn.pack(side=tk.LEFT, padx=6)

        self.status_var = tk.StringVar(value="Готово")
        tk.Label(self, textvariable=self.status_var,
                 bg="#f0f4f8", fg="#555", font=("Arial", 9),
                 anchor="w").pack(fill=tk.X, padx=15)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        self.result_frame = tk.Frame(self.notebook, bg="white")
        self.notebook.add(self.result_frame, text="  Результат  ")
        self._build_result_tab()

        self.log_frame = tk.Frame(self.notebook, bg="white")
        self.notebook.add(self.log_frame, text="  Лог запросов  ")
        self._build_log_tab()

    def _build_result_tab(self):
        cols = ("Поле", "Значение")
        self.result_tree = ttk.Treeview(
            self.result_frame, columns=cols, show="headings", height=18)
        self.result_tree.heading("Поле",     text="Поле",     anchor=tk.W)
        self.result_tree.heading("Значение", text="Значение", anchor=tk.W)
        self.result_tree.column("Поле",     width=220, stretch=False)
        self.result_tree.column("Значение", width=620)

        vsb = ttk.Scrollbar(self.result_frame, orient=tk.VERTICAL,
                             command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_tree.pack(fill=tk.BOTH, expand=True)

    def _build_log_tab(self):
        cols = ("ID", "IP клиента", "Домен", "Время запроса", "Регистратор", "Статус")
        self.log_tree = ttk.Treeview(
            self.log_frame, columns=cols, show="headings", height=18)
        for col in cols:
            self.log_tree.heading(col, text=col, anchor=tk.W)
        self.log_tree.column("ID",           width=50,  stretch=False)
        self.log_tree.column("IP клиента",   width=130, stretch=False)
        self.log_tree.column("Домен",        width=200)
        self.log_tree.column("Время запроса",width=155, stretch=False)
        self.log_tree.column("Регистратор",  width=110)
        self.log_tree.column("Статус",       width=80,  stretch=False)

        vsb = ttk.Scrollbar(self.log_frame, orient=tk.VERTICAL,
                             command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_tree.pack(fill=tk.BOTH, expand=True)

    def _start_search(self):
        domain = self.domain_var.get().strip()
        if not domain:
            messagebox.showwarning("Ввод", "Введите доменное имя")
            return
        self.search_btn.config(state=tk.DISABLED)
        self.status_var.set(f"Запрос к регистраторам для {domain!r}…")
        threading.Thread(target=self._do_search, args=(domain,), daemon=True).start()

    def _do_search(self, domain: str):
        try:
            resp = requests.get(
                f"{SERVER_URL}/api/whois",
                params={"domain": domain},
                timeout=30,
            )
            resp.raise_for_status()
            payload = resp.json()
        except requests.RequestException as exc:
            self.after(0, self._show_error, str(exc))
            return

        self.after(0, self._show_result, payload)

    def _show_result(self, payload: dict):
        # Очищаем таблицу
        for row in self.result_tree.get_children():
            self.result_tree.delete(row)

        LABELS = {
            "domain":            "Домен",
            "source":            "Источник (регистратор)",
            "queried_at":        "Время запроса",
            "registrar":         "Регистратор домена",
            "registrar_url":     "URL регистратора",
            "creation_date":     "Дата регистрации",
            "updated_date":      "Дата обновления",
            "expiry_date":       "Дата истечения",
            "registrant_name":   "Владелец (имя)",
            "registrant_org":    "Владелец (организация)",
            "registrant_country":"Страна владельца",
            "registrant_email":  "Email владельца",
            "registrant_phone":  "Телефон владельца",
            "admin_name":        "Администратор",
            "admin_email":       "Email администратора",
            "name_servers":      "Name-серверы",
            "dnssec":            "DNSSEC",
            "status":            "Статус домена",
        }

        for key in ("domain", "source", "queried_at"):
            if key in payload:
                self.result_tree.insert("", tk.END,
                                        values=(LABELS.get(key, key), payload[key]))

        data = payload.get("data", {})
        if "error" in data:
            self.result_tree.insert("", tk.END,
                                    values=("Ошибка", data["error"]),
                                    tags=("err",))
            self.result_tree.tag_configure("err", foreground="red")
        else:
            for key, label in LABELS.items():
                if key in ("domain", "source", "queried_at"):
                    continue
                val = data.get(key)
                if val is None:
                    continue
                if isinstance(val, list):
                    val = ", ".join(val)
                self.result_tree.insert("", tk.END, values=(label, val))

        self.status_var.set(f"Готово — {payload.get('domain', '')}")
        self.search_btn.config(state=tk.NORMAL)
        self.notebook.select(0)

    def _show_error(self, msg: str):
        self.status_var.set("Ошибка соединения с сервером")
        self.search_btn.config(state=tk.NORMAL)
        messagebox.showerror("Ошибка", f"Не удалось связаться с сервером:\n{msg}")

    def _load_logs(self):
        self.status_var.set("Загрузка лога…")
        threading.Thread(target=self._do_load_logs, daemon=True).start()

    def _do_load_logs(self):
        try:
            resp = requests.get(f"{SERVER_URL}/api/logs", params={"limit": 100}, timeout=10)
            resp.raise_for_status()
            rows = resp.json()
        except Exception as exc:
            self.after(0, self._show_error, str(exc))
            return
        self.after(0, self._show_logs, rows)

    def _show_logs(self, rows: list):
        for row in self.log_tree.get_children():
            self.log_tree.delete(row)
        for r in rows:
            tag = "err" if r.get("status") == "error" else ""
            self.log_tree.insert("", tk.END,
                                 values=(r["id"], r["client_ip"], r["domain_name"],
                                         r["queried_at"], r["registrar"], r["status"]),
                                 tags=(tag,))
        self.log_tree.tag_configure("err", foreground="red")
        self.status_var.set(f"Лог обновлён — {len(rows)} записей")
        self.notebook.select(1)


if __name__ == "__main__":
    app = WhoisApp()
    app.mainloop()
