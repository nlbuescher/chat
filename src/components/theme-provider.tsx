"use client";

import { useEffect, useState } from "react";
import { ThemeProvider as NextThemesProvider } from "next-themes";

export default function ThemeProvider({ children, ...props }: React.ComponentProps<typeof NextThemesProvider>) {
	let [mounted, setMounted] = useState(false);

	useEffect(() => setMounted(true));

	if (!mounted) {
		return <>{children}</>;
	}

	return <NextThemesProvider {...props}>{children}</NextThemesProvider>;
}
