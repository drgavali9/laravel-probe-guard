<?php

namespace ProbeGuard\LaravelProbeGuard\Filament\Resources\BlockedIps;

use BackedEnum;
use Filament\Actions\Action;
use Filament\Actions\ActionGroup;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteBulkAction;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\TernaryFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use ProbeGuard\LaravelProbeGuard\Contracts\BlockRepository;
use ProbeGuard\LaravelProbeGuard\Filament\Resources\BlockedIps\Pages\ManageBlockedIps;
use ProbeGuard\LaravelProbeGuard\Models\BlockedIp;
use UnitEnum;

class BlockedIpResource extends Resource
{
    protected static ?string $model = BlockedIp::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedShieldExclamation;

    protected static UnitEnum|string|null $navigationGroup = null;

    protected static ?string $navigationLabel = 'Blocked IPs';

    protected static ?string $modelLabel = 'Blocked IP';

    protected static ?string $pluralModelLabel = 'Blocked IPs';

    public static function getNavigationGroup(): string|UnitEnum|null
    {
        return config('probe-guard.filament.navigation_group', 'Security');
    }

    public static function canCreate(): bool
    {
        return false;
    }

    public static function canEdit($record): bool
    {
        return false;
    }

    public static function form(Schema $schema): Schema
    {
        return $schema->components([]);
    }

    public static function table(Table $table): Table
    {
        return $table
            ->defaultSort('last_attempt_at', 'desc')
            ->columns([
                TextColumn::make('ip_address')->label('IP')->searchable()->sortable()->copyable(),
                TextColumn::make('reason')->searchable()->wrap()->toggleable(),
                TextColumn::make('severity')->badge()->sortable()->toggleable(),
                TextColumn::make('path')->searchable()->limit(48)->tooltip(fn (BlockedIp $record): ?string => $record->path)->toggleable(),
                TextColumn::make('method')->badge()->toggleable(),
                TextColumn::make('hit_count')->label('Hits')->numeric()->sortable(),
                TextColumn::make('blocked_until')->dateTime()->sortable()->badge()->color(fn (BlockedIp $record): string => $record->isActive() ? 'danger' : 'gray'),
                TextColumn::make('last_attempt_at')->dateTime()->sortable()->toggleable(),
                TextColumn::make('unblocked_at')->dateTime()->sortable()->toggleable(isToggledHiddenByDefault: true),
            ])
            ->filters([
                TernaryFilter::make('active')
                    ->label('Active blocks')
                    ->queries(
                        true: fn (Builder $query): Builder => $query->active(),
                        false: fn (Builder $query): Builder => $query->whereNotNull('unblocked_at')->orWhere('blocked_until', '<=', now()),
                        blank: fn (Builder $query): Builder => $query,
                    ),
            ])
            ->recordActions([
                ActionGroup::make([
                    Action::make('unblock')
                        ->icon('heroicon-o-lock-open')
                        ->color('success')
                        ->requiresConfirmation()
                        ->action(fn (BlockedIp $record): bool => app(BlockRepository::class)->unblock($record)),
                    Action::make('extend')
                        ->label('Extend block')
                        ->icon('heroicon-o-clock')
                        ->requiresConfirmation()
                        ->action(fn (BlockedIp $record): bool => $record->forceFill([
                            'blocked_until' => ($record->blocked_until?->isFuture() === true ? $record->blocked_until : now())
                                ->copy()
                                ->add(\DateInterval::createFromDateString((string) config('probe-guard.block_duration', '7 days'))),
                            'unblocked_at' => null,
                        ])->save()),
                ])->icon('heroicon-m-ellipsis-vertical')->color('gray')->button()->hiddenLabel(),
            ])
            ->toolbarActions([
                BulkActionGroup::make([
                    DeleteBulkAction::make(),
                ]),
            ]);
    }

    public static function getPages(): array
    {
        return [
            'index' => ManageBlockedIps::route('/'),
        ];
    }
}
