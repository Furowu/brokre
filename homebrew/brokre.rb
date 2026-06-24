class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.14"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.14/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "80989a7e7ff4dd5701506b3a4a3276e2fc56f3781c40cc1f875a06e41d9add62"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.14/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "55b4140fea3cd0f252e0a23a650e99f5bef81df7dd0849851e5c6e685d7125c9"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.14/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "63694b5ee734ffee0a594ed84c441bd9d6aada419a477f8270af1fc13a014eda"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.14/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "30d35d2bd13b7da26b62048d1b49c5b1342f532060b3ea9e7f276d3672f3efb3"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end
