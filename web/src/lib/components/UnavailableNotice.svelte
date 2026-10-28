<script lang="ts">
	import GroupedList from './GroupedList.svelte';
	import GroupedRow from './GroupedRow.svelte';
	import { m } from '$lib/paraglide/messages';
</script>

<GroupedList>
	<GroupedRow label={m.dashboard_unavailable_title()} detail={m.dashboard_unavailable_body()} />
</GroupedList>
