export interface BrowserDownloadEnvironment {
  createObjectURL(blob: Blob): string;
  revokeObjectURL(url: string): void;
  createLink(): HTMLAnchorElement;
  appendLink(link: HTMLAnchorElement): void;
  defer(callback: () => void): void;
}

function browserDownloadEnvironment(): BrowserDownloadEnvironment {
  return {
    createObjectURL: (blob) => URL.createObjectURL(blob),
    revokeObjectURL: (url) => URL.revokeObjectURL(url),
    createLink: () => document.createElement("a"),
    appendLink: (link) => document.body.append(link),
    defer: (callback) => {
      window.setTimeout(callback, 0);
    },
  };
}

export function startBrowserDownload(
  blob: Blob,
  filename: string,
  environment: BrowserDownloadEnvironment = browserDownloadEnvironment(),
): void {
  const url = environment.createObjectURL(blob);
  let link: HTMLAnchorElement | null = null;

  try {
    link = environment.createLink();
    link.href = url;
    link.download = filename;
    environment.appendLink(link);
    link.click();
    link.remove();
  } catch (error) {
    try {
      link?.remove();
    } finally {
      environment.revokeObjectURL(url);
    }
    throw error;
  }

  try {
    environment.defer(() => environment.revokeObjectURL(url));
  } catch (error) {
    environment.revokeObjectURL(url);
    throw error;
  }
}
