class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.29"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.29/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "d148df8d8ff9b52e84b2de563e44846fc1480ca9d155a9a278ada5c7eb3e4ddf"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.29/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "8e54ad04153f6e85fba0cdc75a8ea53eea979b4fe2c11dece9fb066266d81c9f"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.29/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "18729d5813fc3746d6a1b230f02d21bd99a58266cfb374990a58eb3667152f54"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.29/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "048f8f82b78513659df1d7c7063b6f981e69dc7dfcc5dd263566a245c753e3e9"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end
