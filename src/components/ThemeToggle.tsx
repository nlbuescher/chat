"use client";

import { useEffect, useState } from "react";
import { useTheme } from "next-themes";

export default function ThemeToggle() {
	let [mounted, setMounted] = useState(false);
	let { systemTheme, theme, setTheme } = useTheme();

	let currentTheme = theme === "system" ? systemTheme : theme;

	useEffect(() => setMounted(true));

	if (!mounted) {
		return null;
	}

	//TODO padding & style
	return (
		<button
			onClick={() => setTheme(currentTheme === "dark" ? "light" : "dark")}>
			{currentTheme === "dark" ? "☀️" : "🌙"}
		</button>
	);
}
