class Brokr < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokr"
  version "0.1.5"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokr/releases/download/v0.1.5/brokr-x86_64-apple-darwin.tar.gz"
    sha256 "1cbe5ea20899f1144eae35f2d541f173df6790c162bc7bb89c0883c6f64e947c"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokr/releases/download/v0.1.5/brokr-aarch64-apple-darwin.tar.gz"
    sha256 "8f5ccd3a988ee2f9d648e1b90bc585b6999d6d0e6fdeef9260dbc001c5a51356"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokr/releases/download/v0.1.5/brokr-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "5c57952fa8cfe0b3697f899e1bfad7513d969a331383372ba62e552c2fa519ab"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokr/releases/download/v0.1.5/brokr-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "fd459a84aa94147ad59a19a7dde06393ee7daf17a9fbb8cedecd1788f8423c3a"
  end

  def install
    bin.install "brokr"
  end

  test do
    system "#{bin}/brokr", "--version"
  end
end
